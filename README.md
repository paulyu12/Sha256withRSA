# Sha256withRSA

# python2.7

预先安装 pip install pycrypto

# Java

Java 私钥使用 PKCS#8 格式，这是和 python、C++ 不同的，后两者都使用 PKCS#1 格式的私钥，但是公钥都使用 PKCS#8 格式均没问题

# C++

网上还有一种实现 sha256 with rsa 的方案，是使用 openssl 封装好的 rsa_sign, rsa_verify 函数。但测试发现 rsa_sign 签名结果虽然可以被 rsa_verify 验证，但是相同参数但情况下的签名结果与 java 和 python 不同，因此无法在不同语言之间互操作。因此建议使用本仓库中的实现方式。