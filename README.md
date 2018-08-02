Blockchain Demo

简介

   这是一个学习区块连技术的入门示例，
   本例整合了智能合约pow和libp2p
   
Quick Start

Clone blockchain-demo and download the dependency.

git clone https://github.com/xixiloveyou/blockchain-demo $GOPATH/src/github.com/xixiloveyou/blockchain-demo

cd $GOPATH/src/github.com/xixiloveyou/blockchain-demo

go build main.go
 
查看帮助：

./blockchain_p2p_linux -h (自己查看生成的可执行程序名称,这里以blockchain_p2p_linux为例)

Usage of ./blockchain_p2p_linux:
  -d string
    	target peer to dial
  -l int
    	wait for incoming connections
  -secio
    	enable secio
  -seed int
    	set random seed for id generation
      
执行 ：
./blockchain_p2p_linux -l 10000 -secio 

主要参考资料：
   https://blog.csdn.net/erlib/article/details/79953019

