@USER@様へ

以下のURIにあるサーバから、要求した証明書をダウンロードできます。

	@httpd_protocol@://@httpd_host@@httpd_port@

このメールの件名に書かれたシリアル番号を使用してください。
また、以下のリンクをたどりることで、直接サーバから証明書を
インポートすることもできます。(こちらは特に操作を必要としません):

@httpd_protocol@://@httpd_host@@httpd_port@@pub_cgi_url_prefix@/pki?cmd=getcert&key=@SERIAL@&type=CERTIFICATE

あなたの証明書の正当性を検証するために、サーバから
CA証明書(または、PKI chain)をインポートしてください。:

        @httpd_protocol@://@httpd_host@@httpd_port@@pub_htdocs_url_prefix@

少なくともひとつはプライベートキーの安全なバックアップを
取ることを忘れないでください。:紛失した場合、その時点までに
受け取った暗号化済みメッセージを読めなくなります。

最後に、我々のLDAPサーバをあなたのブラウザのリストに
追加することを特に忘れずにお願いします。
以下のアドレスで見れます。

        ldap://@ldap_host@:@ldap_port@/@ca_organization@,@ca_country@

Netscapeから利用する場合、以下のパラメータを用いて新しいディレクトリを
アドレス帳に追加してください。

	Description: @ca_organization@ LDAP Server with Certificates
	LDAP Server: @ldap_host@
	LDAP Port  : @ldap_port@
	Dir Root   : o=@ca_organization@, c=@ca_country@

これでマウスを1クリックするだけで、Netscapeの検索機能によって
直接ユーザの証明書を検索することができます。


				よろしくお願いします。
				@ca_organization@ セキュリティスタッフ一同


