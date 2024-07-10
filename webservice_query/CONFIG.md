Here's a snippet for the `clair-config.yaml` secret in Kubernetes/OpenShift:


```yaml
indexer:
    scanner:
      package:
        webservice_query:
          url: "http://<service>.<namespace>.svc.cluster.local/get-pkgs?id=${ID}&layer=${LAYER}"
          log_unknown: false
          report_unknowns_package: false
```

Most probably you already have a `indexer`, just add the `scanner` branch and fix the `url` value.
