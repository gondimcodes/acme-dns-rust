use std::sync::Arc;
use std::time::Duration;
use hickory_server::{
    authority::{Authority, MessageRequest, ZoneType},
    proto::rr::{Name, RecordType, Record as DnsRecord, LowerName},
    server::{Request, RequestHandler, ResponseHandler, ResponseInfo},
    store::in_memory::InMemoryAuthority,
};
use hickory_server::authority::MessageResponseBuilder;
use std::str::FromStr;
use std::collections::BTreeMap;
use crate::db::DbPool;
use crate::config::Config;
use moka::future::Cache;

use async_trait::async_trait;

#[derive(Clone)]
pub struct AcmeDnsHandler {
    pub db: Arc<DbPool>,
    pub own_domain: Name,
    pub static_authority: Arc<InMemoryAuthority>,
    /// PERF-03: In-memory cache for TXT records with 2-second TTL
    pub txt_cache: Arc<Cache<String, Vec<String>>>,
}

impl AcmeDnsHandler {
    pub fn new(config: &Config, db: Arc<DbPool>) -> Result<Self, String> {
        let domain_str = if config.general.domain.ends_with('.') {
            config.general.domain.clone()
        } else {
            format!("{}.", config.general.domain)
        };

        // SEG-06: replace unwrap() with proper error propagation
        let own_domain = Name::from_str(&domain_str)
            .map_err(|e| format!("Invalid domain '{}': {}", domain_str, e))?;

        // Setup SOA
        let serial = chrono::Utc::now().format("%Y%m%d%H").to_string();
        // PERF-04: compute serial_u32 once
        let serial_u32: u32 = serial.parse().unwrap_or(1);

        let nsname = config.general.nsname.clone();
        let nsadmin = config.general.nsadmin.clone();

        let mut records = BTreeMap::new();

        // Parse static records (split manually and build)
        for rec in &config.general.static_records {
            let parts: Vec<&str> = rec.split_whitespace().collect();
            if parts.len() >= 3 {
                let name_str = if parts[0].ends_with('.') { parts[0].to_string() } else { format!("{}.", parts[0]) };

                // Support both Standard Zonefile format (name class type data) and simplified (name type data)
                let (rtype_str, rdata_str) = if parts.len() >= 4 && (parts[1].to_uppercase() == "IN" || parts[2].to_uppercase() == "IN") {
                    let type_idx = if parts[1].to_uppercase() == "IN" { 2 } else { 1 };
                    let data_start = type_idx + 1;
                    (parts[type_idx], parts[data_start..].join(" "))
                } else {
                    (parts[1], parts[2..].join(" "))
                };

                if let (Ok(name), Ok(rtype)) = (Name::from_str(&name_str), RecordType::from_str(&rtype_str.to_uppercase())) {
                    let mut dns_rec = DnsRecord::new();
                    dns_rec.set_name(name.clone());
                    dns_rec.set_rr_type(rtype);
                    dns_rec.set_ttl(3600);

                    let rdata = match rtype {
                        RecordType::A => {
                            if let Ok(ip) = rdata_str.parse::<std::net::Ipv4Addr>() {
                                Some(hickory_server::proto::rr::RData::A(
                                    hickory_server::proto::rr::rdata::A::from(ip)
                                ))
                            } else { None }
                        }
                        RecordType::AAAA => {
                            if let Ok(ip) = rdata_str.parse::<std::net::Ipv6Addr>() {
                                Some(hickory_server::proto::rr::RData::AAAA(
                                    hickory_server::proto::rr::rdata::AAAA::from(ip)
                                ))
                            } else { None }
                        }
                        RecordType::NS => {
                            let target = if rdata_str.ends_with('.') { rdata_str.clone() } else { format!("{}.", rdata_str) };
                            if let Ok(target_name) = Name::from_str(&target) {
                                Some(hickory_server::proto::rr::RData::NS(
                                    hickory_server::proto::rr::rdata::NS(target_name)
                                ))
                            } else { None }
                        }
                        RecordType::CNAME => {
                            let target = if rdata_str.ends_with('.') { rdata_str.clone() } else { format!("{}.", rdata_str) };
                            if let Ok(target_name) = Name::from_str(&target) {
                                Some(hickory_server::proto::rr::RData::CNAME(
                                    hickory_server::proto::rr::rdata::CNAME(target_name)
                                ))
                            } else { None }
                        }
                        _ => None,
                    };

                    if let Some(data) = rdata {
                        dns_rec.set_data(Some(data));
                        let rrkey = hickory_server::proto::rr::RrKey::new(name.clone().into(), rtype);
                        let record_set = records.entry(rrkey).or_insert_with(|| {
                            hickory_server::proto::rr::RecordSet::new(&name, rtype, serial_u32)
                        });
                        record_set.insert(dns_rec, serial_u32);
                    }
                }
            }
        }

        // Parse SOA — SEG-06: replace unwrap() with map_err
        let soa_name = own_domain.clone();
        let mname_str = if nsname.ends_with('.') { nsname.clone() } else { format!("{}.", nsname) };
        let rname_str = if nsadmin.ends_with('.') { nsadmin.clone() } else { format!("{}.", nsadmin) };

        let mname = Name::from_str(&mname_str)
            .map_err(|e| format!("Invalid nsname '{}': {}", mname_str, e))?;
        let rname = Name::from_str(&rname_str)
            .map_err(|e| format!("Invalid nsadmin '{}': {}", rname_str, e))?;

        let soa_data = hickory_server::proto::rr::rdata::SOA::new(
            mname,
            rname,
            serial_u32,
            28800,
            7200,
            604800,
            86400,
        );

        let mut soa_rec = DnsRecord::new();
        soa_rec.set_name(soa_name.clone());
        soa_rec.set_rr_type(RecordType::SOA);
        soa_rec.set_ttl(86400);
        soa_rec.set_data(Some(hickory_server::proto::rr::RData::SOA(soa_data)));

        let rrkey = hickory_server::proto::rr::RrKey::new(soa_name.clone().into(), RecordType::SOA);
        let record_set = records.entry(rrkey).or_insert_with(|| {
            hickory_server::proto::rr::RecordSet::new(&soa_name, RecordType::SOA, serial_u32)
        });
        record_set.insert(soa_rec, serial_u32);

        // SEG-06: replace .expect() with map_err
        let static_authority = InMemoryAuthority::new(own_domain.clone(), records, ZoneType::Primary, false)
            .map_err(|e| format!("Failed to initialize static zone records: {}", e))?;

        // PERF-03: TXT record cache — 2 second TTL, max 10000 entries
        let txt_cache = Cache::builder()
            .max_capacity(10_000)
            .time_to_live(Duration::from_secs(2))
            .build();

        Ok(Self {
            db,
            own_domain,
            static_authority: Arc::new(static_authority),
            txt_cache: Arc::new(txt_cache),
        })
    }

    fn sanitize_domain_question(&self, name: &Name) -> String {
        let name_str = name.to_string();
        let domain_str = self.own_domain.to_string();
        if name_str.ends_with(&domain_str) {
            let sub = &name_str[..name_str.len() - domain_str.len()];
            if sub.ends_with('.') {
                sub[..sub.len() - 1].to_string()
            } else {
                sub.to_string()
            }
        } else {
            name_str
        }
    }

    /// PERF-03: Cached TXT lookup — checks in-memory cache first, falls back to DB
    async fn get_txt_cached(&self, subdomain: &str) -> Vec<String> {
        if let Some(cached) = self.txt_cache.get(subdomain).await {
            return cached;
        }
        let values = self.db.get_txt_for_domain(subdomain).await.unwrap_or_default();
        self.txt_cache.insert(subdomain.to_string(), values.clone()).await;
        values
    }
}

#[async_trait]
impl RequestHandler for AcmeDnsHandler {
    async fn handle_request<R: ResponseHandler>(
        &self,
        request: &Request,
        mut response_handle: R,
    ) -> ResponseInfo {
        let query = request.query();
        let name = query.name();
        let qtype = query.query_type();

        let name_str = name.to_string();
        let domain_str = self.own_domain.to_string();

        // Enforce strict domain name validation to prevent scanner DoS
        let name_normalized = name_str.trim_end_matches('.').to_lowercase();
        let domain_normalized = domain_str.trim_end_matches('.').to_lowercase();

        let base_domain = if domain_normalized.starts_with("auth.") {
            domain_normalized[5..].to_string()
        } else {
            domain_normalized.clone()
        };

        if !name_normalized.ends_with(&domain_normalized) && !name_normalized.ends_with(&base_domain) {
            let mut err_hdr = hickory_server::proto::op::Header::response_from_request(request.header());
            err_hdr.set_response_code(hickory_server::proto::op::ResponseCode::Refused);
            return ResponseInfo::from(err_hdr);
        }

        // Limit allowed query types
        match qtype {
            RecordType::TXT | RecordType::A | RecordType::AAAA | RecordType::NS | RecordType::SOA => {}
            _ => {
                let mut err_hdr = hickory_server::proto::op::Header::response_from_request(request.header());
                err_hdr.set_response_code(hickory_server::proto::op::ResponseCode::NotImp);
                return ResponseInfo::from(err_hdr);
            }
        }

        // Determine if query is for dynamically handled TXT records
        if qtype == RecordType::TXT {
            let subdomain = self.sanitize_domain_question(&Name::from(name.clone()));
            // PERF-03: use cached lookup
            let values = self.get_txt_cached(&subdomain).await;
            if !values.is_empty() {
                let mut answers = Vec::new();
                for val in values {
                    if !val.is_empty() {
                        let mut txt_rec = DnsRecord::new();
                        txt_rec.set_name(Name::from(name.clone()));
                        txt_rec.set_rr_type(RecordType::TXT);
                        txt_rec.set_ttl(1);
                        txt_rec.set_data(Some(hickory_server::proto::rr::RData::TXT(
                            hickory_server::proto::rr::rdata::TXT::new(vec![val])
                        )));
                        answers.push(txt_rec);
                    }
                }

                if !answers.is_empty() {
                    let mut header = hickory_server::proto::op::Header::response_from_request(request.header());
                    header.set_response_code(hickory_server::proto::op::ResponseCode::NoError);
                    header.set_authoritative(true);

                    let response = MessageResponseBuilder::from_message_request(request)
                        .build(header, &answers, &[], &[], &[]);

                    if let Ok(info) = response_handle.send_response(response).await {
                        return info;
                    } else {
                        let mut err_hdr = hickory_server::proto::op::Header::new();
                        err_hdr.set_response_code(hickory_server::proto::op::ResponseCode::ServFail);
                        return ResponseInfo::from(err_hdr);
                    }
                }
            }
        }

        // Fallback to static records managed by InMemoryAuthority
        let options = hickory_server::authority::LookupOptions::default();
        let lookup_result = self.static_authority.search(request.request_info(), options).await;

        let mut header = hickory_server::proto::op::Header::response_from_request(request.header());
        header.set_authoritative(true);

        match lookup_result {
            Ok(lookup) => {
                header.set_response_code(hickory_server::proto::op::ResponseCode::NoError);
                let answers: Vec<&DnsRecord> = lookup.iter().collect();
                let response = MessageResponseBuilder::from_message_request(request)
                    .build(header, answers, &[], &[], &[]);
                response_handle.send_response(response).await.unwrap_or_else(|_| {
                    let mut err_hdr = hickory_server::proto::op::Header::new();
                    err_hdr.set_response_code(hickory_server::proto::op::ResponseCode::ServFail);
                    ResponseInfo::from(err_hdr)
                })
            }
            Err(_) => {
                header.set_response_code(hickory_server::proto::op::ResponseCode::NXDomain);
                let response = MessageResponseBuilder::from_message_request(request)
                    .build(header, &[], &[], &[], &[]);
                response_handle.send_response(response).await.unwrap_or_else(|_| {
                    let mut err_hdr = hickory_server::proto::op::Header::new();
                    err_hdr.set_response_code(hickory_server::proto::op::ResponseCode::ServFail);
                    ResponseInfo::from(err_hdr)
                })
            }
        }
    }
}

// Implement Authority wrapper so AcmeDnsHandler itself implements the Authority trait
#[async_trait]
impl Authority for AcmeDnsHandler {
    type Lookup = <InMemoryAuthority as Authority>::Lookup;

    fn zone_type(&self) -> ZoneType {
        self.static_authority.zone_type()
    }

    fn is_axfr_allowed(&self) -> bool {
        self.static_authority.is_axfr_allowed()
    }

    async fn update(&self, update: &MessageRequest) -> hickory_server::authority::UpdateResult<bool> {
        self.static_authority.update(update).await
    }

    fn origin(&self) -> &LowerName {
        self.static_authority.origin()
    }

    async fn lookup(
        &self,
        name: &LowerName,
        rtype: RecordType,
        lookup_options: hickory_server::authority::LookupOptions,
    ) -> Result<Self::Lookup, hickory_server::authority::LookupError> {
        // Intercept dynamic TXT queries
        if rtype == RecordType::TXT {
            let subdomain = self.sanitize_domain_question(&Name::from(name.clone()));

            // PERF-03: use cached lookup
            let values = self.get_txt_cached(&subdomain).await;
            if !values.is_empty() {
                let mut record_set = hickory_server::proto::rr::RecordSet::new(&Name::from(name.clone()), RecordType::TXT, 1);
                for val in values {
                    if !val.is_empty() {
                        let mut txt_rec = DnsRecord::new();
                        txt_rec.set_name(Name::from(name.clone()));
                        txt_rec.set_rr_type(RecordType::TXT);
                        txt_rec.set_ttl(1);
                        txt_rec.set_data(Some(hickory_server::proto::rr::RData::TXT(
                            hickory_server::proto::rr::rdata::TXT::new(vec![val])
                        )));
                        record_set.insert(txt_rec, 1);
                    }
                }
                let lookup = hickory_server::authority::AuthLookup::answers(
                    hickory_server::authority::LookupRecords::new(
                        lookup_options,
                        std::sync::Arc::new(record_set)
                    ),
                    None
                );
                return Ok(lookup);
            }
        }

        self.static_authority.lookup(name, rtype, lookup_options).await
    }

    async fn search(
        &self,
        request: hickory_server::server::RequestInfo<'_>,
        lookup_options: hickory_server::authority::LookupOptions,
    ) -> Result<Self::Lookup, hickory_server::authority::LookupError> {
        let name = request.query.name();
        let rtype = request.query.query_type();
        self.lookup(name, rtype, lookup_options).await
    }

    async fn get_nsec_records(
        &self,
        name: &LowerName,
        lookup_options: hickory_server::authority::LookupOptions,
    ) -> Result<Self::Lookup, hickory_server::authority::LookupError> {
        self.static_authority.get_nsec_records(name, lookup_options).await
    }
}
