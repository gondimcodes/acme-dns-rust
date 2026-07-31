use std::sync::Arc;
use std::time::Duration;
use hickory_server::{
    zone_handler::{
        ZoneHandler, ZoneType, AxfrPolicy,
        LookupControlFlow, AuthLookup, LookupRecords, LookupOptions, LookupError,
    },
    proto::rr::{
        Name, RecordType, Record as DnsRecord, LowerName, TSigResponseContext,
        rdata::{A, AAAA, NS, CNAME, TXT, SOA},
    },
    server::{Request, RequestInfo},
    store::in_memory::InMemoryZoneHandler,
};
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
    pub static_authority: Arc<InMemoryZoneHandler>,
    pub txt_cache: Arc<Cache<String, Vec<String>>>,
}

impl AcmeDnsHandler {
    pub fn new(config: &Config, db: Arc<DbPool>) -> Result<Self, String> {
        let domain_str = if config.general.domain.ends_with('.') {
            config.general.domain.clone()
        } else {
            format!("{}.", config.general.domain)
        };

        let own_domain = Name::from_str(&domain_str)
            .map_err(|e| format!("Invalid domain '{}': {}", domain_str, e))?;

        let serial = chrono::Utc::now().format("%Y%m%d%H").to_string();
        let serial_u32: u32 = serial.parse().unwrap_or(1);

        let nsname = config.general.nsname.clone();
        let nsadmin = config.general.nsadmin.clone();

        let mut records = BTreeMap::new();

        // Parse static records (split manually and build)
        for rec in &config.general.static_records {
            let parts: Vec<&str> = rec.split_whitespace().collect();
            if parts.len() >= 3 {
                let (name_str, rtype_str, rdata_str) = if parts.len() == 3 {
                    (parts[0], parts[1], parts[2..].join(" "))
                } else if parts[1].parse::<u32>().is_ok() {
                    (parts[0], parts[2], parts[3..].join(" "))
                } else {
                    (parts[0], parts[1], parts[2..].join(" "))
                };

                let full_name_str = if name_str == "@" {
                    domain_str.clone()
                } else if name_str.ends_with('.') {
                    name_str.to_string()
                } else {
                    format!("{}.{}", name_str, domain_str)
                };

                if let Ok(rec_name) = Name::from_str(&full_name_str) {
                    if let Ok(rtype) = RecordType::from_str(rtype_str) {
                        let parsed_rdata = match rtype {
                            RecordType::A => {
                                rdata_str.parse::<std::net::Ipv4Addr>().ok().map(|ip| hickory_server::proto::rr::RData::A(A(ip)))
                            }
                            RecordType::AAAA => {
                                rdata_str.parse::<std::net::Ipv6Addr>().ok().map(|ip| hickory_server::proto::rr::RData::AAAA(AAAA(ip)))
                            }
                            RecordType::NS => {
                                Name::from_str(&rdata_str).ok().map(|n| hickory_server::proto::rr::RData::NS(NS(n)))
                            }
                            RecordType::CNAME => {
                                Name::from_str(&rdata_str).ok().map(|n| hickory_server::proto::rr::RData::CNAME(CNAME(n)))
                            }
                            _ => None,
                        };

                        if let Some(rdata) = parsed_rdata {
                            let dns_rec = DnsRecord::from_rdata(rec_name.clone(), 86400, rdata);
                            let rrkey = hickory_server::proto::rr::RrKey::new(rec_name.clone().into(), rtype);
                            let record_set = records.entry(rrkey).or_insert_with(|| {
                                hickory_server::proto::rr::RecordSet::new(rec_name.clone(), rtype, 86400)
                            });
                            record_set.insert(dns_rec, 86400);
                        }
                    }
                }
            }
        }

        // Add NS records if configured
        if !nsname.is_empty() {
            let ns_full = if nsname.ends_with('.') { nsname.clone() } else { format!("{}.", nsname) };
            if let Ok(ns_target) = Name::from_str(&ns_full) {
                let ns_rec = DnsRecord::from_rdata(own_domain.clone(), 86400, hickory_server::proto::rr::RData::NS(NS(ns_target)));

                let rrkey = hickory_server::proto::rr::RrKey::new(own_domain.clone().into(), RecordType::NS);
                let record_set = records.entry(rrkey).or_insert_with(|| {
                    hickory_server::proto::rr::RecordSet::new(own_domain.clone(), RecordType::NS, 86400)
                });
                record_set.insert(ns_rec, 86400);
            }
        }

        // Add SOA record
        let mname = if nsname.is_empty() { own_domain.clone() } else { Name::from_str(&if nsname.ends_with('.') { nsname } else { format!("{}.", nsname) }).unwrap_or(own_domain.clone()) };
        let rname = if nsadmin.is_empty() { own_domain.clone() } else { Name::from_str(&if nsadmin.ends_with('.') { nsadmin } else { format!("{}.", nsadmin) }).unwrap_or(own_domain.clone()) };

        let soa_data = SOA::new(
            mname,
            rname,
            serial_u32,
            86400,
            7200,
            3600000,
            1,
        );

        let soa_name = own_domain.clone();
        let soa_rec = DnsRecord::from_rdata(soa_name.clone(), serial_u32, hickory_server::proto::rr::RData::SOA(soa_data));

        let rrkey = hickory_server::proto::rr::RrKey::new(soa_name.clone().into(), RecordType::SOA);
        let record_set = records.entry(rrkey).or_insert_with(|| {
            hickory_server::proto::rr::RecordSet::new(soa_name.clone(), RecordType::SOA, serial_u32)
        });
        record_set.insert(soa_rec, serial_u32);

        let static_authority = InMemoryZoneHandler::new(own_domain.clone(), records, ZoneType::Primary, AxfrPolicy::Deny)
            .map_err(|e| format!("Failed to initialize static zone records: {}", e))?;

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
        let name_str = name.to_string().to_lowercase();
        let domain_str = self.own_domain.to_string().to_lowercase();
        let mut sub = if name_str.ends_with(&domain_str) {
            let s = &name_str[..name_str.len() - domain_str.len()];
            s.trim_end_matches('.').to_string()
        } else {
            name_str.trim_end_matches('.').to_string()
        };

        if sub.starts_with("_acme-challenge.") {
            sub = sub["_acme-challenge.".len()..].to_string();
        }

        sub
    }

    async fn get_txt_cached(&self, subdomain: &str) -> Vec<String> {
        if let Some(cached) = self.txt_cache.get(subdomain).await {
            return cached;
        }
        let values = self.db.get_txt_for_domain(subdomain).await.unwrap_or_default();
        if !values.is_empty() {
            self.txt_cache.insert(subdomain.to_string(), values.clone()).await;
        }
        values
    }
}

#[async_trait]
impl ZoneHandler for AcmeDnsHandler {
    fn origin(&self) -> &LowerName {
        self.static_authority.origin()
    }

    fn zone_type(&self) -> ZoneType {
        self.static_authority.zone_type()
    }

    fn axfr_policy(&self) -> AxfrPolicy {
        self.static_authority.axfr_policy()
    }

    async fn lookup(
        &self,
        name: &LowerName,
        rtype: RecordType,
        request_info: Option<&RequestInfo<'_>>,
        lookup_options: LookupOptions,
    ) -> LookupControlFlow<AuthLookup> {
        let name_str = name.to_string();
        let domain_str = self.own_domain.to_string();

        let name_normalized = name_str.trim_end_matches('.').to_lowercase();
        let domain_normalized = domain_str.trim_end_matches('.').to_lowercase();

        let base_domain = if domain_normalized.starts_with("auth.") {
            domain_normalized[5..].to_string()
        } else {
            domain_normalized.clone()
        };

        if !name_normalized.ends_with(&domain_normalized) && !name_normalized.ends_with(&base_domain) {
            return LookupControlFlow::Break(Err(LookupError::ResponseCode(hickory_server::proto::op::ResponseCode::Refused)));
        }

        // Intercept dynamic TXT queries
        if rtype == RecordType::TXT {
            let subdomain = self.sanitize_domain_question(&Name::from(name.clone()));

            let values = self.get_txt_cached(&subdomain).await;
            if !values.is_empty() {
                let mut record_set = hickory_server::proto::rr::RecordSet::new(Name::from(name.clone()), RecordType::TXT, 1);
                for val in values {
                    if !val.is_empty() {
                        let txt_rec = DnsRecord::from_rdata(
                            Name::from(name.clone()),
                            1,
                            hickory_server::proto::rr::RData::TXT(TXT::new(vec![val])),
                        );
                        record_set.insert(txt_rec, 1);
                    }
                }
                let lookup = AuthLookup::answers(
                    LookupRecords::new(
                        lookup_options,
                        std::sync::Arc::new(record_set)
                    ),
                    None
                );
                return LookupControlFlow::Break(Ok(lookup));
            } else if self.db.get_user_by_subdomain(&subdomain).await.unwrap_or_default().is_some() {
                let lookup = AuthLookup::default();
                return LookupControlFlow::Break(Ok(lookup));
            }
        }

        self.static_authority.lookup(name, rtype, request_info, lookup_options).await
    }

    async fn search(
        &self,
        request: &Request,
        lookup_options: LookupOptions,
    ) -> (LookupControlFlow<AuthLookup>, Option<TSigResponseContext>) {
        if let Ok(request_info) = request.request_info() {
            let name = request_info.query.name();
            let rtype = request_info.query.query_type();
            let lower_name = LowerName::new(name);
            let lookup_flow = self.lookup(&lower_name, rtype, Some(&request_info), lookup_options).await;
            (lookup_flow, None)
        } else {
            (LookupControlFlow::Break(Err(LookupError::ResponseCode(hickory_server::proto::op::ResponseCode::FormErr))), None)
        }
    }

    async fn nsec_records(
        &self,
        name: &LowerName,
        lookup_options: LookupOptions,
    ) -> LookupControlFlow<AuthLookup> {
        self.static_authority.nsec_records(name, lookup_options).await
    }
}
