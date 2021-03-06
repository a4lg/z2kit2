z2kit2: セキュリティキャンプ 2018 (トラック Z2) 用簡易解析フレームワーク
=========================================================================


あとがきとしての、挨拶
-----------------------

このフレームワークは、セキュリティキャンプ 2018 全国大会 トラック Z
“アンチウィルス実装トラック” テーマ Z2 学習と利用の両方のために利用した、
Python 自作簡易解析フレームワーク的な何かです。

参加者のために意図的に空白にした部分やトレーニング内容のその場での変更
(当初想定していなかった顕著なものとしてはファイル毎のエントロピーを計算する `FileEntropyFeature`)、
突貫工事で作った部分のこれまた突貫修正などが入り交じる、
少なくとも git リポジトリ構築のお手本にはしてはいけないものにはなりました。
が、参加者と講師 (忠鉢および大居) の交流と思想をあらわす一次資料ではあります
(コミット自体は全て大居が行いましたが、至る箇所に参加者や忠鉢氏からのフィードバックが反映されています)。

ゼミ参加者の人に対して言うべきこととしては――
このソフトウェア自体を大切にする必要はありませんが、
少なくとも交流記録のひとつとしては大切にしてやってほしいということ。

`z2kit2` は昨年の `z2kit` に引き続き、
時間上の制限から極めてお粗末な部分も多いものとなってしまいましたが、
今回は幾つかの Python 技法 (例えばデコレータなど) の実装例を埋め込むなどもしています。
参加者の人だけでなく、将来なんらかの実装をしようとする人が一人でも参考にしてくれれば、
それはそれで嬉しいものです。

このソフトウェアが直接生かされるかどうかは別として、
これを読まれた方の将来に心からの期待を込めて。

大居　司  跋, 2018-08-27


共通環境の整備
---------------

作業を行うためのディレクトリ (ここでは `$Z2DIR`) を適当に作成し、
その中でこの z2kit リポジトリをクローンしてください。

```shell
mkdir $Z2DIR
cd $Z2DIR
git clone https://github.com/a4lg/z2kit2.git z2kit2
```

このようにすれば、作業用ディレクトリで Python スクリプトを作る際、

```python
from z2kit.elf import *
from z2kit.elffile import *
```

―のような形でこのリポジトリ内のモジュールを参照することができます。


ELF 解析実装例として
---------------------

z2kit2 は、ELF ファイルの簡易的な読み取り機能を提供します。
簡単な機能追加を試してみましょう。


Python 実装例として
--------------------

`zstruct.py` は Python のデコーレーター (decorator) 機能を用いて、
C の構造体に近い形の構造体を自動実装します。

類似機能を持つ `cstruct` と異なりエンディアンが自由であり、
また Python におけるデコレーターとリフレクションの使用例として、
少しは役に立つかもしれません。


ライセンス
-----------

セキュリティキャンプ 2018 の各トラックで頒布するファイル類には、
一部公開禁止のものを含みます。ただ z2kit2 に関しては公開自由です。

	Copyright (C) 2018 Tsukasa OI.

この Python ソースコード類には ISC License を適用します。
詳細は各ソースコードファイルを確認してください。
