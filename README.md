# elixir

Elixir - a magical potion

## Cilium

### Installation with Helm:

Install:

- `helm install cilium cilium/cilium --version 1.15.4 \
--namespace kube-system \
--set eni.enabled=true \
--set ipam.mode=eni \
--set egressMasqueradeInterfaces=eth0 \
--set routingMode=native`

Restart pods:

- `kubectl get pods --all-namespaces -o custom-columns=NAMESPACE:.metadata.namespace,NAME:.metadata.name,HOSTNETWORK:.spec.hostNetwork --no-headers=true | grep '<none>' | awk '{print "-n "$1" "$2}' | xargs -L 1 -r kubectl delete pod`

* Install CLI for testing:

`CILIUM_CLI_VERSION=$(curl -s https://raw.githubusercontent.com/cilium/cilium-cli/main/stable.txt)
CLI_ARCH=amd64
if [ "$(uname -m)" = "aarch64" ]; then CLI_ARCH=arm64; fi
curl -L --fail --remote-name-all https://github.com/cilium/cilium-cli/releases/download/${CILIUM_CLI_VERSION}/cilium-linux-${CLI_ARCH}.tar.gz{,.sha256sum}
sha256sum --check cilium-linux-${CLI_ARCH}.tar.gz.sha256sum
sudo tar xzvfC cilium-linux-${CLI_ARCH}.tar.gz /usr/local/bin
rm cilium-linux-${CLI_ARCH}.tar.gz{,.sha256sum}`

-- Cilium CLI helpful video: [Video Link](https://www.youtube.com/watch?v=ndjmaM1i0WQ&t=1136s)

## Hubble

Install:

- `helm upgrade cilium cilium/cilium --version 1.15.4 \
--namespace kube-system \
--reuse-values \
--set hubble.relay.enabled=true \
--set hubble.ui.enabled=true`

* Install UI Client for hubble ([Hubble UI Guide](https://docs.cilium.io/en/stable/gettingstarted/hubble_setup/#install-the-hubble-client)):

`HUBBLE_VERSION=$(curl -s https://raw.githubusercontent.com/cilium/hubble/master/stable.txt)
HUBBLE_ARCH=amd64
if [ "$(uname -m)" = "aarch64" ]; then HUBBLE_ARCH=arm64; fi
curl -L --fail --remote-name-all https://github.com/cilium/hubble/releases/download/$HUBBLE_VERSION/hubble-linux-${HUBBLE_ARCH}.tar.gz{,.sha256sum}
sha256sum --check hubble-linux-${HUBBLE_ARCH}.tar.gz.sha256sum
sudo tar xzvfC hubble-linux-${HUBBLE_ARCH}.tar.gz /usr/local/bin
rm hubble-linux-${HUBBLE_ARCH}.tar.gz{,.sha256sum}`

- Validate access and observe:

\*\* `cilium hubble port-forward&`

Useful link for policy enforcement: [docs](https://docs.cilium.io/en/stable/security/http/#gs-http) [example] (https://docs.cilium.io/en/stable/gettingstarted/demo/#starwars-demo)

Add UI: `cilium hubble enable`

- Hubble [cheat-sheet](https://isovalent.wpengine.com/wp-content/uploads/2023/08/Cilium-Hubble-Cheat-Sheet.png)

## WebCoPilot:

Allows you to check web-related vulnerabilities

- Opensource [repo](https://github.com/h4r5h1t/webcopilot)

## Pentesting:

- SessionProbe [repo](https://github.com/dub-flow/sessionprobe)

- Mosint is an automated email osint tool written in Go that allows you investigate for target emails in a fast and efficient manner. It consolidates numerous services, enabling security researchers to swiftly access a wealth of information. [repo] (https://github.com/alpkeskin/mosint)

## LLMs Security:

- Security scanner for LLM prompts [repo] (https://github.com/deadbits/vigil-llm)

-

## Malware & CVEs

- CVEs Map [article] (https://www.helpnetsecurity.com/2024/02/01/cvemap-query-browse-search-cve/)

## Wazuh

- Wazuh [site](https://wazuh.com/platform/overview/)

## K8S Compliance

- Kubescape is an open-source Kubernetes security platform for your IDE, CI/CD pipelines, and clusters. It includes risk analysis, security, compliance, and misconfiguration scanning, saving Kubernetes users and administrators precious time, effort, and resource [repo](https://github.com/kubescape/kubescape). Don't forget to run `export PATH=$PATH:/home/matan/.kubescape/bin` after installation

- See all issues with how to solve them in k8s - `kubescape scan -v --format json --output ecv.json` [demo](https://kubescape.io/#demo)

- Another tool worth considering is: Kubeshark [website](https://www.kubeshark.co/)

- https://falco.org/

## SBOMS

- Software Bill of Materials (SBOM) from container images and filesystems. Can be done with: [repo](https://github.com/anchore/syft) and [repo] (https://github.com/anchore/grype)

- https://github.com/bom-squad/protobom

## General

- Good article for open-source tools: https://www.helpnetsecurity.com/2024/01/04/open-source-cybersecurity-tools/
