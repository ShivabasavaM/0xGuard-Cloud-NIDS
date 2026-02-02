# 0xGuard - Unsupervised Cloud-Native NIDS

**0xGuard** is an autonomous network security system that detects zero-day intrusions using Unsupervised Learning. This repository hosts the **Cloud Inference Microservice**, a containerized REST API designed for high-throughput, real-time traffic analysis.



## ⚡ System Architecture

Unlike traditional firewalls that rely on static signatures, 0xGuard utilizes an **Isolation Forest** algorithm to establish a baseline of "normal" network behavior. It calculates anomaly scores for every network flow in real-time, allowing it to flag polymorphic attacks (DDOS, Port Scans, Probe floods) without prior knowledge of the attack vector.

**Technical Stack:**
* **Core Engine:** Python 3.9, Scikit-Learn (Isolation Forest)
* **API Layer:** FastAPI (Asynchronous High-Performance Web Framework)
* **Containerization:** Docker (Multi-stage builds)
* **Deployment:** AWS EC2 (T3.micro / Ubuntu LTS)
* **Security:** API Key Authentication (Header-based)

## 🚀 Live Demonstration

The production API is currently deployed on AWS EC2.

* **Base URL:** `http://3.27.13.225`
* **Interactive Documentation (Swagger UI):** [http://3.27.13.225/docs](http://3.27.13.225/docs)

**Access Credentials:**
> To prevent abuse, the API is protected. Please use the following key during testing:
> **X-API-Key:** `0xGuard_1`

## 🛠️ Local Installation

### Prerequisites
* Docker Engine 20.10+
* Git

### Deployment Steps
1.  **Clone the repository**
    ```bash
    git clone [https://github.com/YOUR_USERNAME/0xGuard-Cloud-API.git](https://github.com/YOUR_USERNAME/0xGuard-Cloud-API.git)
    cd 0xGuard-Cloud-API
    ```

2.  **Build the Container**
    ```bash
    docker build -t 0xguard-cloud .
    ```

3.  **Run the Service**
    ```bash
    docker run -d -p 80:80 -e API_KEY="my_secret_key" 0xguard-cloud
    ```

## 🔌 API Usage

**Endpoint:** `POST /analyze`

**Request Headers:**
* `Content-Type: application/json`
* `X-API-Key: <YOUR_KEY>`

**Payload Example (Normal Traffic):**
```json
{
  "dst_port": 443,
  "protocol": 6,
  "flow_packets": 15,
  "flow_bytes": 1200,
  "flow_duration": 0.5,
  "packet_rate": 30.0,
  "byte_rate": 2400.0,
  "tcp_flags_sum": 2
}
```
**Response (Normal Traffic):**
```json
{
  "status": "SAFE",
  "action": "ALLOW",
  "anomaly_score": 0.15,
  "details": "Traffic analyzed successfully"
}
