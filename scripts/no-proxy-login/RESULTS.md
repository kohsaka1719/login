# ビルドした Azure Login の NO_PROXY 比較結果

更新前と PR #630 のソースをそれぞれビルドし、実 GitHub OIDC と実 Azure CLI
ログインで比較した。全8条件が期待どおりとなり、全ジョブが success で完了した。

## 実行情報

- [成功した実行](https://github.com/kohsaka1719/login/actions/runs/40177097729)
- 日付: 2026-10-25（ログの検証時刻は17:33–17:34 JST）
- 実行ブランチ: `verify-pr-630`
- 実行したworkflow／検証コードのSHA: `ada9a4eb98e95d12bbf9e1ad6ecf5f35c7fda7c3`
- [実行したworkflow](https://github.com/kohsaka1719/login/blob/ada9a4eb98e95d12bbf9e1ad6ecf5f35c7fda7c3/.github/workflows/no-proxy-login.yml)
- Environment: `Automation test`、OIDC認証先: SP1
- runner: `ubuntu-latest`、Node: `v24.21.0`
- 依存関係は各ソースのlockfileを `npm ci` で導入し、core自身が解決するhttp-clientの版を確認した。

| 比較対象 | ソースSHA | core | http-client |
| --- | --- | --- | --- |
| 更新前（PRの親コミット） | `fcd03407c33dcc2d7daa4be58fbc6cc97f863e47` | 1.11.1 | 2.0.1 |
| PR #630 | `f6a8c089320d041a212e55c4dfb04f742398fbe1` | 2.0.3 | 3.0.2 |

## 条件と実測

- OIDC取得先: `run-actions-3-azure-eastus.actions.githubusercontent.com`
- 親ドメイン: `actions.githubusercontent.com`
- 不一致ドメイン: `no-proxy-repro.invalid`
- 一時HTTP CONNECTプロキシ: `http://127.0.0.1:3128`
- OIDC取得先だけを403で拒否し、それ以外のHTTPS接続を中継した。
- 小文字の `https_proxy` / `http_proxy` / `no_proxy` をloginステップに設定し、
  大文字の変数は空にして競合を排除した。

| 条件 | 更新前のログイン | PR版のログイン | 更新前OIDC拒否数 | PR版OIDC拒否数 | 更新前Azure接続数 | PR版Azure接続数 | 判定 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| プロキシなし | 成功 | 成功 | 0 | 0 | 0 | 0 | PASS |
| 完全なhostnameを除外 | 成功 | 成功 | 0 | 0 | 2 | 2 | PASS |
| 親ドメインを除外 | OIDC取得失敗 | 成功 | 1 | 0 | 1 | 2 | PASS |
| 無関係なドメインを除外 | OIDC取得失敗 | OIDC取得失敗 | 1 | 1 | 1 | 1 | PASS |

接続数は事前のプロキシ動作確認を除外し、Action実行中のものだけを数えた。
Azure接続数は `login.microsoftonline.com` へのCONNECT数であり、ログイン成功回数ではない。
失敗条件でもOIDC取得前のCLI処理により1接続を観測している。
成功した5条件すべてで、CLIの現在のclient ID・tenant ID・subscription IDがSP1と一致した。

- [更新前・親ドメイン](https://github.com/kohsaka1719/login/actions/runs/40177097729/job/121120035363)
- [PR版・親ドメイン](https://github.com/kohsaka1719/login/actions/runs/40177097729/job/121120035345)

## 成果物の同一性

`lib/main/index.js` のSHA256は各variantの4条件すべてで一致した。

| 比較対象 | main bundle SHA256 |
| --- | --- |
| 更新前 | `72af9dbae64fc6a9a200dcc44e09197e28a827b0d2e923f01ebc8431ff33f6a3` |
| PR版 | `f506bfce1f752257668891a4522a7c2201f3ba2a1604b52fbdc2299c07ac6b29` |

Actionのソースを改変せず `uses: ./action-under-test` で実行した。
ビルド後から実行後までmain／cleanup両bundleのハッシュが変わっていないことも検査した。

## 確認できた範囲

この条件では、PR #630のビルド成果物で、親ドメイン指定のNO_PROXYがGitHub OIDC
取得先に適用され、実Azureログインまで成功した。更新前の成果物では同じ指定が効かず、
OIDC取得先へのCONNECTがプロキシで拒否された。完全一致と不一致の対照条件も期待どおりだった。

対象はUbuntu、AzureCloud、CLIのOIDCログイン、小文字のプロキシ環境変数である。
PowerShellのプロキシ経路や、他OS・他cloud・すべてのNO_PROXY書式を検証した結果ではない。
既存の通常Live Testsは[別の実行で全件成功](https://github.com/kohsaka1719/login/actions/runs/40173723318)している。
RG等のAzureリソースは、この追加検証では作成していない。

初回の[別ブランチでの実行](https://github.com/kohsaka1719/login/actions/runs/40176856496)は、
Environmentのブランチ制限によりジョブ開始前に拒否された。
保護ルールは変更せず、許可済みの `verify-pr-630` で再実行した。
