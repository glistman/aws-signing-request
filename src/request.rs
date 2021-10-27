use chrono::DateTime;
use chrono::Utc;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

use crate::{
    error::SigningError,
    hasher::{calculate_sha_256, calulate_hmac_sha_256},
    url_encode::{self, encode_url},
};

const HEADERS_TO_INGORE: [&str; 2] = ["connection", "x-amzn-trace-id"];

pub const X_AMZ_CONTENT_SHA256: &str = "x-amz-content-sha256";
pub const X_AMZ_DATE: &str = "x-amz-date";
pub const AUTHORIZATION: &str = "Authorization";
pub const AWS_JSON_CONTENT_TYPE: &str = "application/x-amz-json-1.0";
pub const X_AWZ_TARGET: &str = "X-Amz-Target";
pub const X_AMZ_SECURITY_TOKEN: &str = "X-Amz-Security-Token";

#[derive(Debug)]
pub struct AWSDate {
    pub iso_8601: String,
    pub date: String,
}

pub struct CanonicalRequest<'a> {
    pub method: &'a str,
    pub path: String,
    pub params: String,
    pub headers: String,
    pub singed_headers: String,
    pub content_sha_256: String,
    pub date: AWSDate,
    aws_access_key_id: &'a str,
    aws_secret_access_key: &'a str,
    region: &'a str,
    service: &'a str,
}

pub struct CanonicalRequestBuilder<'a> {
    method: &'a str,
    path: &'a str,
    params: BTreeMap<&'a str, Vec<&'a str>>,
    headers: BTreeMap<&'a str, &'a str>,
    body: &'a str,
    aws_access_key_id: &'a str,
    aws_secret_access_key: &'a str,
    region: &'a str,
    service: &'a str,
}

impl<'a> CanonicalRequestBuilder<'a> {
    pub fn new(
        host: &'a str,
        method: &'a str,
        path: &'a str,
        aws_access_key_id: &'a str,
        aws_secret_access_key: &'a str,
        region: &'a str,
        service: &'a str,
    ) -> CanonicalRequestBuilder<'a> {
        let mut headers = BTreeMap::new();
        headers.insert("Host", host);

        CanonicalRequestBuilder {
            method,
            path,
            params: BTreeMap::new(),
            headers,
            body: "",
            aws_access_key_id,
            aws_secret_access_key,
            region,
            service,
        }
    }

    pub fn body(&'a mut self, body: &'a str) -> &'a mut Self {
        self.body = body;
        self
    }

    pub fn header(&'a mut self, name: &'a str, value: &'a str) -> &'a mut Self {
        self.headers.insert(name, value);
        self
    }

    pub fn header_opt(&'a mut self, name: &'a str, value: Option<&'a str>) -> &'a mut Self {
        if let Some(value) = value {
            self.headers.insert(name, value);
        }
        self
    }

    pub fn header_opt_ref(&'a mut self, name: &'a str, value: &'a Option<String>) -> &'a mut Self {
        if let Some(value) = value {
            self.headers.insert(name, value);
        }
        self
    }

    pub fn param(&'a mut self, name: &'a str, value: &'a str) -> &'a mut Self {
        self.params.insert(name, vec![value]);
        self
    }

    pub fn param_list(&'a mut self, name: &'a str, values: Vec<&'a str>) -> &'a mut Self {
        self.params.insert(name, values);
        self
    }

    pub fn build(&self, date: DateTime<Utc>) -> CanonicalRequest {
        CanonicalRequest::new(
            self.method,
            self.path,
            self.params.to_owned(),
            self.headers.to_owned(),
            self.body,
            date,
            self.aws_access_key_id,
            self.aws_secret_access_key,
            self.region,
            self.service,
        )
    }
}

impl<'a> CanonicalRequest<'a> {
    pub fn new(
        method: &'a str,
        path: &'a str,
        params: BTreeMap<&str, Vec<&str>>,
        headers: BTreeMap<&str, &str>,
        body: &'a str,
        date: DateTime<Utc>,
        aws_access_key_id: &'a str,
        aws_secret_access_key: &'a str,
        region: &'a str,
        service: &'a str,
    ) -> CanonicalRequest<'a> {
        let mut headers = CanonicalRequest::extract_and_lowercase_and_sort_header_names(&headers);
        let content_sha_256 = calculate_sha_256(body);
        let date = AWSDate {
            iso_8601: date.format("%Y%m%dT%H%M%SZ").to_string(),
            date: date.format("%Y%m%d").to_string(),
        };

        headers.insert(X_AMZ_CONTENT_SHA256.to_string(), content_sha_256.clone());
        headers.insert(X_AMZ_DATE.to_string(), date.iso_8601.clone());

        CanonicalRequest {
            method: method,
            path: CanonicalRequest::to_canononical_resource_path(path),
            params: CanonicalRequest::to_canonical_query_string(params),
            headers: CanonicalRequest::to_canonical_headers(&headers),
            singed_headers: CanonicalRequest::to_cannonical_signed_headers(&headers),
            content_sha_256,
            date,
            aws_access_key_id,
            aws_secret_access_key,
            region,
            service,
        }
    }

    pub fn to_canonical_request(&self) -> String {
        let mut canonical_request = String::new();
        canonical_request.push_str(&self.method);
        canonical_request.push('\n');
        canonical_request.push_str(&self.path);
        canonical_request.push('\n');
        canonical_request.push_str(&self.params);
        canonical_request.push('\n');
        canonical_request.push_str(&self.headers);
        canonical_request.push('\n');
        canonical_request.push_str(&self.singed_headers);
        canonical_request.push('\n');
        canonical_request.push_str(&self.content_sha_256);
        canonical_request
    }

    pub fn calculate_authorization(&self) -> Result<String, SigningError> {
        let scope = self.create_scope();
        let string_to_sign = self.create_string_to_sign(&scope);
        let signing_key =
            self.create_singning_key(self.aws_secret_access_key, self.region, self.service)?;

        let signature = hex::encode(calulate_hmac_sha_256(&signing_key, &string_to_sign)?);

        Ok(format!(
            "AWS4-HMAC-SHA256 Credential={}/{},SignedHeaders={},Signature={}",
            self.aws_access_key_id, scope, &self.singed_headers, signature
        ))
    }

    fn create_scope(&self) -> String {
        format!(
            "{}/{}/{}/aws4_request",
            &self.date.date, self.region, self.service
        )
    }

    fn create_string_to_sign(&self, scope: &str) -> String {
        format!(
            "AWS4-HMAC-SHA256\n\
        {}\n\
        {}\n\
        {}",
            &self.date.iso_8601,
            scope,
            &self.get_as_sha_256(),
        )
    }

    fn get_as_sha_256(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.to_canonical_request());
        format!("{:X}", hasher.finalize()).to_lowercase()
    }

    fn create_singning_key(
        &self,
        aws_secret_access_key: &str,
        region: &str,
        service: &str,
    ) -> Result<Vec<u8>, SigningError> {
        let k_secret = format!("AWS4{}", aws_secret_access_key);
        let k_date = calulate_hmac_sha_256(k_secret.as_bytes(), &self.date.date)?;
        let k_region = calulate_hmac_sha_256(&k_date, region)?;
        let k_service = calulate_hmac_sha_256(&k_region, service)?;
        calulate_hmac_sha_256(&k_service, "aws4_request")
    }

    fn to_canononical_resource_path(path: &str) -> String {
        let path = url_encode::encode_url_path(path);
        if path.ends_with("/") && path.len() > 1 {
            path[0..path.len() - 1].to_owned()
        } else {
            path[..].to_owned()
        }
    }

    fn to_canonical_query_string(params: BTreeMap<&str, Vec<&str>>) -> String {
        let mut cannonical_query_string = String::new();
        let mut first_iteration = true;
        for (key, mut values) in params {
            let encoded_key = encode_url(&key);
            if values.is_empty() {
                if first_iteration {
                    first_iteration = false;
                } else {
                    cannonical_query_string.push_str("&");
                }
                cannonical_query_string.push_str(&encoded_key);
                cannonical_query_string.push_str("=");
            } else {
                values.sort();
                for value in &values {
                    let encoded_value = encode_url(value);
                    if first_iteration {
                        first_iteration = false;
                    } else {
                        cannonical_query_string.push_str("&");
                    }
                    cannonical_query_string.push_str(&encoded_key);
                    cannonical_query_string.push_str("=");
                    cannonical_query_string.push_str(&encoded_value);
                }
            }
        }
        cannonical_query_string
    }

    fn extract_and_lowercase_and_sort_header_names(
        headers: &BTreeMap<&'a str, &'a str>,
    ) -> BTreeMap<String, String> {
        let mut sorted_headers = BTreeMap::new();
        for (key, value) in headers {
            let header_name = key.to_lowercase();
            if !HEADERS_TO_INGORE.contains(&header_name.as_str()) {
                sorted_headers.insert(header_name, value.to_string());
            }
        }
        sorted_headers
    }

    fn to_canonical_headers(sorted_headers: &BTreeMap<String, String>) -> String {
        let mut canonical_headers = String::new();

        for (name, value) in sorted_headers {
            canonical_headers.push_str(CanonicalRequest::compact_string(name).as_str());
            canonical_headers.push(':');
            canonical_headers.push_str(CanonicalRequest::compact_string(value).as_str());
            canonical_headers.push('\n');
        }

        canonical_headers
    }

    fn compact_string(string: &str) -> String {
        let mut previous_is_white_space = false;
        let mut compact_string = String::new();
        for char in string.chars() {
            if !previous_is_white_space && char == ' ' {
                previous_is_white_space = true;
                compact_string.push(char);
            } else if char != ' ' {
                compact_string.push(char);
                previous_is_white_space = false;
            }
        }
        compact_string
    }

    fn to_cannonical_signed_headers(sorted_headers: &BTreeMap<String, String>) -> String {
        let mut signed_headers = String::new();
        for (name, _) in sorted_headers {
            if !signed_headers.is_empty() {
                signed_headers.push(';');
            }
            signed_headers.push_str(name);
        }
        signed_headers
    }
}

#[cfg(test)]
mod tests {

    use chrono::{TimeZone, Utc};
    use std::collections::BTreeMap;

    use crate::request::{CanonicalRequest, CanonicalRequestBuilder};

    #[test]
    fn canononical_resource_path_preserve_slash() {
        assert_eq!(
            &CanonicalRequest::to_canononical_resource_path("/path"),
            "/path"
        );
    }

    #[test]
    fn canononical_resource_path_preserve_slash_with_end_slash() {
        assert_eq!(
            &CanonicalRequest::to_canononical_resource_path("/path/"),
            "/path"
        );
    }

    #[test]
    fn canononical_resource_path_encode_plus() {
        assert_eq!(
            &CanonicalRequest::to_canononical_resource_path("/path+"),
            "/path%2B"
        );
    }

    #[test]
    fn canononical_resource_path_encode_plus_with_end_slash() {
        assert_eq!(
            &CanonicalRequest::to_canononical_resource_path("/path+/"),
            "/path%2B"
        );
    }

    #[test]
    fn canononical_resource_path_encode_asterisk() {
        assert_eq!(
            &CanonicalRequest::to_canononical_resource_path("/path*"),
            "/path%2A"
        );
    }

    #[test]
    fn canononical_resource_path_encode_asterisk_with_end_slash() {
        assert_eq!(
            &CanonicalRequest::to_canononical_resource_path("/path*/"),
            "/path%2A"
        );
    }

    #[test]
    fn canononical_resource_path_encode_tiled_operator() {
        assert_eq!(
            &CanonicalRequest::to_canononical_resource_path("/path~"),
            "/path~"
        );
    }

    #[test]
    fn canononical_resource_path_encode_tiled_operator_with_end_slash() {
        assert_eq!(
            &CanonicalRequest::to_canononical_resource_path("/path~/"),
            "/path~"
        );
    }

    #[test]
    fn canonical_query_string_single_param() {
        let mut params = BTreeMap::new();
        params.insert("Cparam", vec!["1"]);
        params.insert("Bparam", vec!["2"]);
        params.insert("Aparam", vec!["3"]);
        assert_eq!(
            &CanonicalRequest::to_canonical_query_string(params),
            "Aparam=3&Bparam=2&Cparam=1"
        );
    }

    #[test]
    fn canonical_query_string_multiple_param() {
        let mut params = BTreeMap::new();
        params.insert("Cparam", vec!["1", "4"]);
        params.insert("Bparam", vec!["2"]);
        params.insert("Aparam", vec!["5", "3"]);
        assert_eq!(
            &CanonicalRequest::to_canonical_query_string(params),
            "Aparam=3&Aparam=5&Bparam=2&Cparam=1&Cparam=4"
        );
    }

    #[test]
    fn compact_string() {
        assert_eq!(
            &CanonicalRequest::compact_string("    h ello         world!      "),
            " h ello world! "
        );
    }

    #[test]
    fn canonical_headers() {
        let mut headers = BTreeMap::new();
        headers.insert("X-Amz-Target", "Timestream_20181101.WriteRecords");
        headers.insert(
            "X-Amz-Content-Sha256",
            "beaead3198f7da1e70d03ab969765e0821b24fc913697e929e726aeaebf0eba3",
        );
        headers.insert("Content-Type", "application/x-amz-json-1.0");
        headers.insert("X-Amz-Date", "20211016T223709Z");

        let headers = CanonicalRequest::extract_and_lowercase_and_sort_header_names(&headers);
        assert_eq!(
            &CanonicalRequest::to_canonical_headers(&headers),
            "content-type:application/x-amz-json-1.0\n\
            x-amz-content-sha256:beaead3198f7da1e70d03ab969765e0821b24fc913697e929e726aeaebf0eba3\n\
            x-amz-date:20211016T223709Z\n\
            x-amz-target:Timestream_20181101.WriteRecords\n"
        );
    }

    #[test]
    fn cannonical_signed_headers() {
        let mut headers = BTreeMap::new();
        headers.insert("X-Amz-Target", "Timestream_20181101.WriteRecords");
        headers.insert(
            "X-Amz-Content-Sha256",
            "beaead3198f7da1e70d03ab969765e0821b24fc913697e929e726aeaebf0eba3",
        );
        headers.insert("Content-Type", "application/x-amz-json-1.0");
        headers.insert("X-Amz-Date", "20211016T223709Z");

        let headers = CanonicalRequest::extract_and_lowercase_and_sort_header_names(&headers);
        assert_eq!(
            &CanonicalRequest::to_cannonical_signed_headers(&headers),
            "content-type;x-amz-content-sha256;x-amz-date;x-amz-target"
        );
    }

    #[test]
    fn cannonical_request_aws_example_1() {
        let date = Utc.ymd(2013, 5, 24).and_hms(0, 0, 0);

        let mut canonical_request_buillder = CanonicalRequestBuilder::new(
            "examplebucket.s3.amazonaws.com",
            "GET",
            "/",
            "AKIAIOSFODNN7EXAMPLE",
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "us-east-1",
            "s3",
        );

        let canonical_requuest = canonical_request_buillder
            .param_list("lifecycle", Vec::new())
            .build(date);

        assert_eq!(
            &canonical_requuest.to_canonical_request(),
            "GET\n\
            /\n\
            lifecycle=\n\
            host:examplebucket.s3.amazonaws.com\n\
            x-amz-content-sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n\
            x-amz-date:20130524T000000Z\n\
            \n\
            host;x-amz-content-sha256;x-amz-date\n\
            e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn cannonical_request_aws_example_2() {
        let date = Utc.ymd(2013, 5, 24).and_hms(0, 0, 0);

        let mut canonical_request_builder = CanonicalRequestBuilder::new(
            "examplebucket.s3.amazonaws.com",
            "GET",
            "/",
            "AKIAIOSFODNN7EXAMPLE",
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "us-east-1",
            "s3",
        );

        let canonical_requuest = canonical_request_builder
            .param("max-keys", "2")
            .param("prefix", "J")
            .build(date);

        assert_eq!(
            &canonical_requuest.to_canonical_request(),
            "GET\n\
            /\n\
            max-keys=2&prefix=J\n\
            host:examplebucket.s3.amazonaws.com\n\
            x-amz-content-sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n\
            x-amz-date:20130524T000000Z\n\
            \n\
            host;x-amz-content-sha256;x-amz-date\n\
            e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn cannonical_request_aws_example_3() {
        let date = Utc.ymd(2013, 5, 24).and_hms(0, 0, 0);

        let mut canonical_request_builder = CanonicalRequestBuilder::new(
            "examplebucket.s3.amazonaws.com",
            "GET",
            "/test.txt",
            "AKIAIOSFODNN7EXAMPLE",
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "us-east-1",
            "s3",
        );

        let canonical_requuest = canonical_request_builder
            .header("range", "bytes=0-9")
            .build(date);

        assert_eq!(
            &canonical_requuest.to_canonical_request(),
            "GET\n\
            /test.txt\n\
            \n\
            host:examplebucket.s3.amazonaws.com\n\
            range:bytes=0-9\n\
            x-amz-content-sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n\
            x-amz-date:20130524T000000Z\n\
            \n\
            host;range;x-amz-content-sha256;x-amz-date\n\
            e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn signing_request_aws_example_1() {
        let date = Utc.ymd(2013, 5, 24).and_hms(0, 0, 0);

        let mut canonical_request_builder = CanonicalRequestBuilder::new(
            "examplebucket.s3.amazonaws.com",
            "GET",
            "/test.txt",
            "AKIAIOSFODNN7EXAMPLE",
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "us-east-1",
            "s3",
        );

        let canonical_requuest = canonical_request_builder
            .header("range", "bytes=0-9")
            .build(date);

        assert_eq!(
            &canonical_requuest.calculate_authorization().unwrap(),
            "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request,SignedHeaders=host;range;x-amz-content-sha256;x-amz-date,Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"
        );
    }

    #[test]
    fn signing_request_aws_example_2() {
        let date = Utc.ymd(2013, 5, 24).and_hms(0, 0, 0);

        let mut canonical_request_buillder = CanonicalRequestBuilder::new(
            "examplebucket.s3.amazonaws.com",
            "GET",
            "/",
            "AKIAIOSFODNN7EXAMPLE",
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "us-east-1",
            "s3",
        );

        let canonical_requuest = canonical_request_buillder
            .param_list("lifecycle", Vec::new())
            .build(date);

        assert_eq!(
            &canonical_requuest.calculate_authorization().unwrap(),
            "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request,SignedHeaders=host;x-amz-content-sha256;x-amz-date,Signature=fea454ca298b7da1c68078a5d1bdbfbbe0d65c699e0f91ac7a200a0136783543"
        );
    }
}
