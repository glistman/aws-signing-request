# AWS Sign V4

This is a rust implementation for request signing based on the following documentation https://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-header-based-auth.html

## Usage
You just need to create a Canonical Request and calculate the authorization and add the headers to your client

```bash
use aws_signing_request::request::{AUTHORIZATION, CanonicalRequestBuilder, X_AMZ_CONTENT_SHA256, X_AMZ_DATE};
use aws_signing_request::request::{AWS_JSON_CONTENT_TYPE, X_AWZ_TARGET};
use chrono::Utc;

#[tokio::main]
async fn main() {
    let host = "ingest.timestream.us-east-1.amazonaws.com";
    let body = "{}";

    let canonical_request = CanonicalRequestBuilder::new(
        host,
        "POST",
        "/",
        "AKIAIOSFODNN7EXAMPLE",
        "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "us-east-1",
        "timestream",
    ).header("Content-Type", AWS_JSON_CONTENT_TYPE)
     .header(X_AWZ_TARGET, "Timestream_20181101.DescribeEndpoints")
     .body(body)
     .build(Utc::now());

    let client = reqwest::Client::new();

    let endpoint = client
        .post(format!("https://{}", host))
        .header(X_AMZ_DATE, &canonical_request.date.iso_8601)
        .header("Content-Type", AWS_JSON_CONTENT_TYPE)
        .header(X_AWZ_TARGET, "Timestream_20181101.DescribeEndpoints")
        .header(X_AMZ_CONTENT_SHA256, &canonical_request.content_sha_256)
        .header(
            AUTHORIZATION,
            &canonical_request
                .calculate_authorization()
                .expect("Authorization creation failed"),
        )
        .body(body)
        .send()
        .await
        .expect("Service error")
        .text()
        .await
        .unwrap();

    println!("{:?}", endpoint);
}
```

## Usage With Session Token
For the session token, you just need to add the X-Amz-Security-Token header to the canonical request and the actual request.

```bash
use aws_signing_request::request::{AUTHORIZATION, CanonicalRequestBuilder, X_AMZ_CONTENT_SHA256, X_AMZ_DATE};
use aws_signing_request::request::{AWS_JSON_CONTENT_TYPE, X_AWZ_TARGET, X_AMZ_SECURITY_TOKEN};
use chrono::Utc;

#[tokio::main]
async fn main() {
    let host = "ingest.timestream.us-east-1.amazonaws.com";
    let body = "{}";
    let aws_session_token = "MDENG/bPxRfiCYEXAMPLEKEY";

    let canonical_request = CanonicalRequestBuilder::new(
        host,
        "POST",
        "/",
        "AKIAIOSFODNN7EXAMPLE",
        "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "us-east-1",
        "timestream",
    ).header("Content-Type", AWS_JSON_CONTENT_TYPE)
     .header(X_AMZ_SECURITY_TOKEN, aws_session_token)
     .header(X_AWZ_TARGET, "Timestream_20181101.DescribeEndpoints")
     .body(body)
     .build(Utc::now());

    let client = reqwest::Client::new();

    let endpoint = client
        .post(format!("https://{}", host))
        .header(X_AMZ_DATE, &canonical_request.date.iso_8601)
        .header("Content-Type", AWS_JSON_CONTENT_TYPE)
        .header(X_AWZ_TARGET, "Timestream_20181101.DescribeEndpoints")
        .header(X_AMZ_CONTENT_SHA256, &canonical_request.content_sha_256)
        .header(X_AMZ_SECURITY_TOKEN, aws_session_token)
        .header(
            AUTHORIZATION,
            &canonical_request
                .calculate_authorization()
                .expect("Authorization creation failed"),
        )
        .body(body)
        .send()
        .await
        .expect("Service error")
        .text()
        .await
        .unwrap();

    println!("{:?}", endpoint);
}
```

## Usage
[Full example](https://github.com/glistman/aws-signing-request-example)

## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

Please make sure to update tests as appropriate.

## License
[MIT](https://choosealicense.com/licenses/mit/)