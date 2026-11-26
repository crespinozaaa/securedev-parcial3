pipeline {
    agent any

    stages {
        stage('1. Checkout Código') {
            steps {
                git branch: 'main', url: 'https://github.com/crespinozaaa/securedev-parcial3.git'
            }
        }

        stage('2. Build & SAST (Bandit)') {
            steps {
                sh '''
                    docker build -t securedev-webapp:latest .
                    docker run --rm securedev-webapp:latest bandit -r app.py init_db.py -s B104
                '''
            }
        }

        stage('3. Despliegue App & Monitorización') {
            steps {
                sh '''
                    docker network create securedev-net || true
                    docker rm -f webapp node-exporter prometheus grafana || true

                    docker run -d --name webapp --network securedev-net -p 5000:5000 securedev-webapp:latest
                    docker run -d --name node-exporter --network securedev-net -p 9100:9100 prom/node-exporter:latest

                    docker create --name prometheus --network securedev-net -p 9090:9090 prom/prometheus:latest
                    docker cp prometheus.yml prometheus:/etc/prometheus/prometheus.yml
                    docker start prometheus

                    docker run -d --name grafana --network securedev-net -p 3000:3000 grafana/grafana:latest
                    sleep 5
                '''
            }
        }

        stage('4. DAST (OWASP ZAP)') {
            steps {
                sh '''
                    docker run --rm --network securedev-net ghcr.io/zaproxy/zaproxy:stable zap-baseline.py -t http://webapp:5000 -I
                '''
            }
        }
    }
}
