利用者の皆様へ

あなたの証明書(シリアル番号:@__SERIAL__@, DN:@__DN__@)が
生成されました。以下のURIにおいて、サーバからすぐにダウンロードできます。

	@httpd_protocol@://@httpd_host@@httpd_port@

シリアル番号を使用してください。
また、以下のリンクをたどることで、サーバから直接証明書を
インポートすることもできます。(こちらは特に操作を必要としません)

@httpd_protocol@://@httpd_host@@httpd_port@@pub_cgi_url_prefix@/pki?cmd=getcert&key=@__SERIAL__@&type=CERTIFICATE

あなたの証明書の正当性を検証するために、サーバから
CA証明書(またはPKI chain)をインポートしてください。

	@httpd_protocol@://@httpd_host@@httpd_port@@pub_htdocs_url_prefix@

少なくともひとつはプライベートキーの安全なバックアップを
取ることを忘れないでください。:もし紛失した場合、その時点までに
受け取った暗号化済みメッセージを読めなくなります。

よろしくお願いします。
@ca_organization@ セキュリティスタッフ一同
