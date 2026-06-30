# ExtMCP Guardrails

ExtMCP server for mcp guardrails

# TODO

- [ ] how to generate python stub;
- [ ] `proto/ext_mcp_pb2.py`, `proto/ext_mcp_pb2_grpc.py` is missing;
- [ ] missing workflow;
- [ ] more tests;

# Example

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: extmcp-guardrail
  namespace: agent-system
spec:
  replicas: 2
  selector:
    matchLabels: { app: extmcp-guardrail }
  template:
    metadata:
      labels: { app: extmcp-guardrail }
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 65532
        fsGroup: 65532
        seccompProfile: { type: RuntimeDefault }
      containers:
        - name: guardrail
          image: ghcr.io/soulwhisper/extmcp-guardrail:0.1.0
          ports:
            - { containerPort: 9001, name: grpc-h2c }
          env:
            - { name: FAILURE_MODE, value: "failClosed" }
            - {
                name: OTEL_EXPORTER_OTLP_ENDPOINT,
                value: "http://otel-collector.observability.svc:4317",
              }
            - {
                name: INVARIANT_RULES_PATH,
                value: "/etc/guardrails/rules.policy",
              }
          resources:
            requests: { cpu: "500m", memory: "2Gi" }
            limits: { cpu: "2", memory: "4Gi" }
          readinessProbe:
            grpc: { port: 9001, service: "grpc.health.v1.Health" }
            initialDelaySeconds: 5
            periodSeconds: 5
          livenessProbe:
            grpc: { port: 9001 }
            initialDelaySeconds: 30
            periodSeconds: 15
          volumeMounts:
            - { name: rules, mountPath: /etc/guardrails, readOnly: true }
      volumes:
        - name: rules
          configMap: { name: guardrail-rules }
---
apiVersion: v1
kind: Service
metadata:
  name: extmcp-guardrail
  namespace: agent-system
spec:
  selector: { app: extmcp-guardrail }
  ports:
    - {
        port: 4445,
        targetPort: 9001,
        protocol: TCP,
        appProtocol: kubernetes.io/h2c,
      }
```
