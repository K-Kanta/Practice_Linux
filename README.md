# Practice_Linux
LittleHTTPはシンプルなHTTPサーバーです。このサーバーはC言語で書かれており、軽量で高速なWebサーバーを構築するために使用できます。
## インストール
LittleHTTPはコンパイルしてインストールする必要があります。以下はコンパイルとインストールの手順です。
1. ソースコードをダウンロードします。
2. ターミナルでソースコードのディレクトリに移動します。
3. コンパイルします。
```
gcc -o httpd2 httpd2.c -lm
```
## サーバーで実行
```
./littlehttp [--port=ポート番号] [--chroot --user=ユーザー名 --group=グループ名] [--debug] <ドキュメントルートディレクトリ>
```
* --port: サーバーがリッスンするポート番号を指定します。デフォルトはポート80です
* --chroot: サーバーをchrootモードで実行します。
* --user: chrootモードで実行する際のユーザー名を指定します。
* --group: chrootモードで実行する際のグループ名を指定します。
* --debug: デバッグモードでサーバーを実行します。