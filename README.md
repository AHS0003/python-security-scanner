# Python SAST Agent

A lightweight, rule-based Static Application Security Testing (SAST) tool for Python code. It detects potentially dangerous code patterns, groups findings by severity, and exposes scan results through a Flask REST API.

The application has been containerized with Docker, deployed on a local Kubernetes cluster using kind, and instrumented with Prometheus metrics.

## Implemented features

- Python static analysis with six detection rules.
- Findings classified as `CRITICAL`, `HIGH`, `MEDIUM`, or `LOW`, with remediation guidance.
- JSON scan reports through a Flask REST API.
- Prometheus metrics for scans and detected findings.
- Docker image using Gunicorn to serve the API.
- Kubernetes Deployment, Service, and health probes.
- ServiceMonitor for Prometheus discovery.
- Prometheus, Grafana, and Alertmanager installed using Helm.

> This is a pattern-based scanner. Detected patterns indicate potential security issues; they are not proof of exploitability.

## Technologies

Python · Flask · Prometheus Client · Gunicorn · Docker · Kubernetes (kind) · Helm · Prometheus · Grafana · Alertmanager

## Project files

```text
python-security-scanner/
├── security_scanner.py
├── api.py
├── sample_vulnerable.py
├── requirements.txt
├── Dockerfile
├── .dockerignore
├── k8s/
│   ├── namespace.yaml
│   ├── deployment.yaml
│   ├── service.yaml
│   └── servicemonitor.yaml
├── monitoring/
│   └── values.yaml
└── README.md
```

## Run locally

Requires Python 3.10+.

```bash
git clone https://github.com/AHS0003/python-security-scanner.git
cd python-security-scanner
# While changes are under review:
git switch feature/prometheus-monitoring
python -m pip install -r requirements.txt
python api.py
```

The API listens on `http://localhost:5000` by default.

### API endpoints

| Method | Endpoint | Description |
| --- | --- | --- |
| `GET` | `/health` | Check API health |
| `GET` | `/rules` | List detection rules |
| `POST` | `/scan/code` | Scan Python code submitted as JSON |
| `POST` | `/scan/file` | Scan an uploaded `.py` file |
| `GET` | `/metrics` | Expose Prometheus metrics |

Example scan:

```bash
curl -X POST http://localhost:5000/scan/code \
  -H 'Content-Type: application/json' \
  -d '{"code":"password = \"admin123\"\neval(\"1+1\")"}'
```

## Prometheus metrics

| Metric | Type | Meaning |
| --- | --- | --- |
| `sast_scans_total` | Counter | Successful API scans |
| `sast_findings_total{severity="..."}` | Counter | Cumulative findings by severity |
| `sast_last_scan_findings{severity="..."}` | Gauge | Findings by severity in the latest scan |

```bash
curl -s http://localhost:5000/metrics | grep '^sast_'
```

Metrics are kept in the process memory and reset when the application restarts. The Docker setup uses one Gunicorn worker.

## Docker

```bash
docker build -t python-sast-agent:monitoring .
docker run --rm --name sast-monitoring -p 5001:5000 python-sast-agent:monitoring
```

In a second terminal:

```bash
curl http://localhost:5001/health
curl http://localhost:5001/metrics
```

## Kubernetes (kind)

Requires Docker Desktop, kind, and kubectl.

```bash
# Create the cluster if it does not already exist
kind create cluster --name obs --wait 120s
kubectl config use-context kind-obs
kind load docker-image python-sast-agent:monitoring --name obs

kubectl apply -f k8s/namespace.yaml
kubectl apply -f k8s/deployment.yaml
kubectl apply -f k8s/service.yaml
kubectl get pods -n sast-monitoring
```

The SAST Pod was tested as `1/1 Running`. To access the API locally:

```bash
kubectl -n sast-monitoring port-forward svc/sast-agent 5002:5000
```

In a second terminal:

```bash
curl http://localhost:5002/health
curl http://localhost:5002/metrics
```

A test scan in Kubernetes updated `sast_scans_total` and reported one `CRITICAL` and one `HIGH` finding.

## Prometheus monitoring

Install the monitoring stack with Helm:

```bash
helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
helm repo update
helm upgrade --install monitoring prometheus-community/kube-prometheus-stack \
  --namespace monitoring --create-namespace \
  --values monitoring/values.yaml --wait --timeout 15m

kubectl apply -f k8s/servicemonitor.yaml
kubectl get servicemonitors -n sast-monitoring
kubectl get pods -n monitoring
```

The `sast-agent` ServiceMonitor was created and discovered by Prometheus.

Access Prometheus:

```bash
kubectl -n monitoring port-forward svc/monitoring-kube-prometheus-prometheus 9090:9090
```

Go to `http://localhost:9090` and query:

```promql
up{job="sast-agent"}
sast_scans_total
sast_last_scan_findings{severity="CRITICAL"}
```

Grafana and Alertmanager are installed as part of the Helm stack. To access Grafana:

```bash
kubectl -n monitoring port-forward svc/monitoring-grafana 3000:80
```

Open `http://localhost:3000` and log in as `admin`. Retrieve the password locally with:

```bash
kubectl -n monitoring get secret monitoring-grafana \
  -o jsonpath='{.data.admin-password}' | base64 -d
```

Do not commit passwords or other secrets to the repository.
