import CryptoKit
import Foundation

enum AWSWorkbench {
    static let services = ["S3", "SQS", "DynamoDB", "IAM", "STS"]

    static let operations: [String: [String]] = [
        "S3": ["ListBuckets", "CreateBucket", "ListObjectsV2", "PutObject", "GetObject", "DeleteObject", "DeleteBucket"],
        "SQS": ["ListQueues", "CreateQueue", "GetQueueUrl", "SendMessage", "ReceiveMessage", "DeleteMessage", "DeleteQueue", "PurgeQueue"],
        "DynamoDB": ["ListTables", "CreateTable", "DescribeTable", "PutItem", "GetItem", "UpdateItem", "Query", "Scan", "DeleteItem", "DeleteTable"],
        "IAM": ["ListUsers", "CreateUser", "GetUser", "DeleteUser"],
        "STS": ["GetCallerIdentity"]
    ]

    static func browseOperation(for service: String) -> String? {
        switch service {
        case "S3": return "ListBuckets"
        case "SQS": return "ListQueues"
        case "DynamoDB": return "ListTables"
        case "IAM": return "ListUsers"
        case "STS": return "GetCallerIdentity"
        default: return nil
        }
    }

    static func defaultPayload(for operation: String) -> String {
        switch operation {
        case "CreateBucket", "DeleteBucket": return #"{"Bucket":"example-bucket"}"#
        case "ListObjectsV2", "PutObject", "GetObject", "DeleteObject":
            return #"{"Bucket":"example-bucket","Key":"example.txt","Body":"hello from Localite"}"#
        case "CreateQueue": return #"{"QueueName":"example-queue"}"#
        case "GetQueueUrl": return #"{"QueueName":"example-queue"}"#
        case "SendMessage":
            return #"{"QueueUrl":"http://localhost:4566/000000000000/example-queue","MessageBody":"hello from Localite"}"#
        case "ReceiveMessage", "DeleteQueue", "PurgeQueue":
            return #"{"QueueUrl":"http://localhost:4566/000000000000/example-queue"}"#
        case "DeleteMessage":
            return #"{"QueueUrl":"http://localhost:4566/123456789012/example-queue","ReceiptHandle":"paste-a-receipt-handle"}"#
        case "CreateTable":
            return #"{"TableName":"example-table","KeySchema":[{"AttributeName":"id","KeyType":"HASH"}],"AttributeDefinitions":[{"AttributeName":"id","AttributeType":"S"}],"BillingMode":"PAY_PER_REQUEST"}"#
        case "PutItem":
            return #"{"TableName":"example-table","Item":{"id":{"S":"one"},"value":{"S":"hello"}}}"#
        case "GetItem", "DeleteItem":
            return #"{"TableName":"example-table","Key":{"id":{"S":"one"}}}"#
        case "DescribeTable", "DeleteTable":
            return #"{"TableName":"example-table"}"#
        case "UpdateItem":
            return ##"{"TableName":"example-table","Key":{"id":{"S":"one"}},"UpdateExpression":"SET #value = :value","ExpressionAttributeNames":{"#value":"value"},"ExpressionAttributeValues":{":value":{"S":"updated"}},"ReturnValues":"ALL_NEW"}"##
        case "Query":
            return ##"{"TableName":"example-table","KeyConditionExpression":"#id = :id","ExpressionAttributeNames":{"#id":"id"},"ExpressionAttributeValues":{":id":{"S":"one"}}}"##
        case "CreateUser", "GetUser", "DeleteUser":
            return #"{"UserName":"example-user"}"#
        default: return "{}"
        }
    }

    static func perform(service: String, operation: String, payloadText: String,
                        completion: @escaping (Result<String, Error>) -> Void) {
        do {
            let request = try makeRequest(service: service, operation: operation, payloadText: payloadText)
            URLSession.shared.dataTask(with: request) { data, response, error in
                if let error {
                    completion(.failure(error))
                    return
                }
                guard let http = response as? HTTPURLResponse, let data else {
                    completion(.failure(WorkbenchError.invalidResponse))
                    return
                }
                completion(.success("HTTP \(http.statusCode)\n" + format(data)))
            }.resume()
        } catch {
            completion(.failure(error))
        }
    }

    private enum WorkbenchError: LocalizedError {
        case invalidPayload
        case missingParameter(String)
        case unsupportedOperation
        case invalidResponse

        var errorDescription: String? {
            switch self {
            case .invalidPayload: return "Parameters must be a JSON object."
            case .missingParameter(let name): return "This operation needs the “\(name)” parameter."
            case .unsupportedOperation: return "This operation is not available in the current emulator."
            case .invalidResponse: return "The emulator returned an invalid HTTP response."
            }
        }
    }

    private static func makeRequest(service: String, operation: String, payloadText: String) throws -> URLRequest {
        guard let payloadData = payloadText.data(using: .utf8),
              let parameters = try JSONSerialization.jsonObject(with: payloadData) as? [String: Any] else {
            throw WorkbenchError.invalidPayload
        }

        var method = "POST"
        var path = "/"
        var query = ""
        var body = Data()
        var headers: [String: String] = [:]

        switch service {
        case "STS", "IAM":
            let version = service == "STS" ? "2011-06-15" : "2010-05-08"
            var fields = ["Action": operation, "Version": version]
            for (key, value) in parameters {
                fields[key] = value as? String ?? String(describing: value)
            }
            body = Data(fields.keys.sorted().map { "\(formEncode($0))=\(formEncode(fields[$0] ?? ""))" }
                .joined(separator: "&").utf8)
            headers["Content-Type"] = "application/x-www-form-urlencoded; charset=utf-8"
        case "SQS", "DynamoDB":
            let target = service == "SQS" ? "AmazonSQS.\(operation)" : "DynamoDB_20120810.\(operation)"
            body = try JSONSerialization.data(withJSONObject: parameters, options: [.sortedKeys])
            headers["Content-Type"] = "application/x-amz-json-1.0"
            headers["X-Amz-Target"] = target
        case "S3":
            switch operation {
            case "ListBuckets":
                method = "GET"
            case "CreateBucket", "DeleteBucket":
                method = "PUT"
                if operation == "DeleteBucket" { method = "DELETE" }
                path = "/\(pathEncode(try requiredString("Bucket", in: parameters)))"
            case "ListObjectsV2":
                method = "GET"
                path = "/\(pathEncode(try requiredString("Bucket", in: parameters)))"
                query = "list-type=2"
            case "PutObject":
                method = "PUT"
                path = try s3ObjectPath(parameters)
                guard let text = parameters["Body"] as? String else {
                    throw WorkbenchError.missingParameter("Body")
                }
                body = Data(text.utf8)
            case "GetObject":
                method = "GET"
                path = try s3ObjectPath(parameters)
            case "DeleteObject":
                method = "DELETE"
                path = try s3ObjectPath(parameters)
            default:
                throw WorkbenchError.unsupportedOperation
            }
        default:
            throw WorkbenchError.unsupportedOperation
        }

        let urlString = "http://localhost:4566\(path)" + (query.isEmpty ? "" : "?\(query)")
        guard let url = URL(string: urlString) else { throw WorkbenchError.invalidPayload }
        var request = URLRequest(url: url)
        request.httpMethod = method
        request.httpBody = body.isEmpty ? nil : body
        for (name, value) in headers { request.setValue(value, forHTTPHeaderField: name) }
        sign(&request, service: service.lowercased(), path: path, query: query, body: body)
        return request
    }

    private static func sign(_ request: inout URLRequest, service: String, path: String, query: String, body: Data) {
        let now = Date()
        let timestamp = DateFormatter.localiteSigV4.string(from: now)
        let date = String(timestamp.prefix(8))
        let region = "us-east-1"
        let host = "localhost:4566"
        let signedHeaders = "host;x-amz-content-sha256;x-amz-date"
        let payloadHash = hex(SHA256.hash(data: body))
        let canonicalHeaders = "host:\(host)\nx-amz-content-sha256:\(payloadHash)\nx-amz-date:\(timestamp)\n"
        let canonicalRequest = "\(request.httpMethod ?? "GET")\n\(path)\n\(query)\n\(canonicalHeaders)\n\(signedHeaders)\n\(payloadHash)"
        let scope = "\(date)/\(region)/\(service)/aws4_request"
        let stringToSign = "AWS4-HMAC-SHA256\n\(timestamp)\n\(scope)\n\(hex(SHA256.hash(data: Data(canonicalRequest.utf8))))"
        let kDate = hmac(Data("AWS4test".utf8), Data(date.utf8))
        let kRegion = hmac(kDate, Data(region.utf8))
        let kService = hmac(kRegion, Data(service.utf8))
        let kSigning = hmac(kService, Data("aws4_request".utf8))
        let signature = hex(hmac(kSigning, Data(stringToSign.utf8)))
        request.setValue(timestamp, forHTTPHeaderField: "X-Amz-Date")
        request.setValue(payloadHash, forHTTPHeaderField: "X-Amz-Content-Sha256")
        request.setValue(
            "AWS4-HMAC-SHA256 Credential=test/\(scope), SignedHeaders=\(signedHeaders), Signature=\(signature)",
            forHTTPHeaderField: "Authorization"
        )
    }

    private static func s3ObjectPath(_ parameters: [String: Any]) throws -> String {
        let bucket = try requiredString("Bucket", in: parameters)
        let key = try requiredString("Key", in: parameters)
        let encodedKey = key.split(separator: "/", omittingEmptySubsequences: false)
            .map { pathEncode(String($0)) }.joined(separator: "/")
        return "/\(pathEncode(bucket))/\(encodedKey)"
    }

    private static func requiredString(_ key: String, in parameters: [String: Any]) throws -> String {
        guard let value = parameters[key] as? String, !value.isEmpty else {
            throw WorkbenchError.missingParameter(key)
        }
        return value
    }

    private static func formEncode(_ value: String) -> String {
        value.utf8.map { byte in
            if (byte >= 65 && byte <= 90) || (byte >= 97 && byte <= 122) ||
                (byte >= 48 && byte <= 57) || "-._~".utf8.contains(byte) {
                return String(UnicodeScalar(byte))
            }
            return String(format: "%%%02X", byte)
        }.joined()
    }

    private static func pathEncode(_ value: String) -> String {
        formEncode(value)
    }

    private static func hmac(_ key: Data, _ message: Data) -> Data {
        Data(HMAC<SHA256>.authenticationCode(for: message, using: SymmetricKey(data: key)))
    }

    private static func hex<S: Sequence>(_ bytes: S) -> String where S.Element == UInt8 {
        bytes.map { String(format: "%02x", $0) }.joined()
    }

    private static func format(_ data: Data) -> String {
        if let object = try? JSONSerialization.jsonObject(with: data),
           let pretty = try? JSONSerialization.data(withJSONObject: object, options: [.prettyPrinted, .sortedKeys]),
           let text = String(data: pretty, encoding: .utf8) {
            return text
        }
        if let xml = try? XMLDocument(data: data, options: [.nodePreserveAll]),
           let pretty = xml.xmlString(options: [.nodePrettyPrint]) as String? {
            return pretty
        }
        return String(data: data, encoding: .utf8) ?? data.map { String(format: "%02x", $0) }.joined()
    }
}

private extension DateFormatter {
    static let localiteSigV4: DateFormatter = {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = TimeZone(secondsFromGMT: 0)
        formatter.dateFormat = "yyyyMMdd'T'HHmmss'Z'"
        return formatter
    }()
}
