
# enterprise_2tier 验证环境复现步骤

## 前置条件

- Python 3.12+, pyyaml, click, pydantic, python-dotenv
- Docker + ContainerLab (`clab`)
- 配置 `.env`: `LLM_API_KEY`, `LLM_BASE_URL`, `LLM_MODEL`

```bash
# .env 示例（容器内 DNS 不可达域名时需用 IP）
LLM_MODEL=deepseek-v4-flash
LLM_BASE_URL=http://<API_HOST_IP>
LLM_API_KEY=sk-xxx
```

## 1. 构建 clab-agent 镜像（加入 openai SDK）

```bash
cat > /tmp/Dockerfile.agent << 'EOF'
FROM clab-agent:latest
RUN pip install openai --no-cache-dir
EOF
docker build -t clab-agent:latest /tmp -f /tmp/Dockerfile.agent
```

## 2. 构建 dmz-web runtime 镜像（加入 PG 工具链）

```bash
# CVE-2012-1823 (PHP CGI)
docker build --network=host \
  -t cvelab-runtime-2012-1823-592f83a6d939 \
  -f data/atoms/CVE-2012-1823/runtime/Dockerfile \
  data/atoms/CVE-2012-1823/runtime

# CVE-2022-22965 (Spring4Shell)
docker build --network=host \
  -t cvelab-runtime-2022-22965-b954ca0d33e2 \
  -f data/atoms/CVE-2022-22965/runtime/Dockerfile \
  data/atoms/CVE-2022-22965/runtime

# CVE-2019-17558 (Solr)
docker build --network=host \
  -t cvelab-runtime-2019-17558-9a0ecf29fcdb \
  -f data/atoms/CVE-2019-17558/runtime/Dockerfile \
  data/atoms/CVE-2019-17558/runtime

# CVE-2018-16509 (ImageMagick)
docker build --network=host \
  -t cvelab-runtime-2018-16509-6690af7aec2e \
  -f data/atoms/CVE-2018-16509/runtime/Dockerfile \
  data/atoms/CVE-2018-16509/runtime
```

## 3. Tag 源镜像为 runtime 镜像

```bash
# CVE-2019-9193 (PostgreSQL)
docker tag vulhub/postgres:10.7 cvelab-runtime-2019-9193-e8b2723eae7f

# CVE-2022-22965 源镜像（已由步骤 2 构建，无需额外操作）
```

## 4. 静态验证（不部署）

```bash
PYTHONPATH=src python3 -c "
from clab_builder.orchestrator.composer.scenario import ScenarioPipeline
p = ScenarioPipeline(templates_dir='templates', atoms_dir='data/atoms', default_validation_mode='guided_agent')
out = p.generate(template_name='enterprise_2tier', cve_ids=['CVE-2012-1823', 'CVE-2014-3120'], scenario_name='test-2tier')
nodes = out['clab']['topology']['nodes']
print('nodes:', list(nodes.keys()))
print('attack_path:', [s['target_node'] for s in out['ground_truth']['attack_path']])
"
# 期望: nodes=['attacker', 'edge-router', 'data-router', 'target-1', 'target-2']
# 期望: attack_path=['target-1', 'target-2']
```

## 5. 环境部署验证（无 Agent）

```bash
sudo -E env HOME="$HOME" PATH="$PATH" PYTHONPATH="$PWD/src" python3 \
scripts/verify_enterprise2_guided_batch.py \
  --case-manifest data/range_matrices/enterprise_2tier_agent.json \
  --max-cases 1 \
  --agent-context l2 --noise-level none \
  --parallel 1 --max-turns 50 --agent-timeout 1800 \
  --model deepseek-v4-flash \
  --environment-only \
  --output data/guide_ablation/2tier_env_test
```

检查 `summary.json`：`environment_success=True`, `attack_graph_valid=True`, `attack_path_reachable=True`。

## 6. L2 Agent 端到端验证

### 无 noise

```bash
sudo -E env HOME="$HOME" PATH="$PATH" PYTHONPATH="$PWD/src" python3 \
scripts/verify_enterprise2_guided_batch.py \
  --case-manifest data/range_matrices/enterprise_2tier_agent.json \
  --max-cases 1 \
  --agent-context guided --noise-level none \
  --agent-runner openai \
  --parallel 1 --max-turns 80 --agent-timeout 2400 \
  --model deepseek-v4-flash \
  --output data/guide_ablation/2tier_agent_test
```

检查 `verify_result.json`：`guided_trial_success=True`, `objective_achieved=True`, 两个 flag 均为 `match=True`。

### 带 noise

```bash
for level in low medium high; do
  sudo -E env HOME="$HOME" PATH="$PATH" PYTHONPATH="$PWD/src" python3 \
  scripts/verify_enterprise2_guided_batch.py \
    --case-manifest data/range_matrices/enterprise_2tier_agent.json \
    --max-cases 1 \
    --agent-context guided --noise-level "$level" \
    --agent-runner openai \
    --parallel 1 --max-turns 80 --agent-timeout 2400 \
    --model deepseek-v4-flash \
    --output "data/guide_ablation/2tier_noise_${level}"
done
```

## 7. 完整矩阵批量测试

已验证的 6 dmz-web × 3 data-store = 18 组合：

```bash
sudo -E env HOME="$HOME" PATH="$PATH" PYTHONPATH="$PWD/src" python3 \
scripts/verify_enterprise2_guided_batch.py \
  --case-manifest data/range_matrices/enterprise_2tier_full.json \
  --max-cases 18 \
  --agent-context guided --noise-level none \
  --agent-runner openai \
  --parallel 2 --max-turns 80 --agent-timeout 2400 \
  --model deepseek-v4-flash \
  --output data/guide_ablation/2tier_full_matrix
```

## 验证通过的组合

| dmz-web | ES 1.1.1 | ES 1.4.2 | PG 10.7 |
|---------|:---:|:---:|:---:|
| CVE-2012-1823 (PHP CGI) | ✅ | ✅ | ✅ |
| CVE-2022-22965 (Spring4Shell) | ✅ | ✅ | ✅ |
| CVE-2017-11610 (Supervisor) | ✅ | ✅ | ✅ |
| CVE-2022-24816 (GeoServer) | ✅ | ✅ | ✅ |
| CVE-2019-17558 (Solr) | ✅ | ✅ | ✅ |
| CVE-2018-16509 (ImageMagick) | ✅ | ✅ | ✅ |
