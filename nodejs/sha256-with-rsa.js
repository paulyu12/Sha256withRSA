const crypto = require('crypto');
fs = require("fs");


const sha256WithRSA = () => {

  var m_privateKey = fs.readFileSync("private-key.pem", "utf8");
  var m_publicKey = fs.readFileSync("public-key.pem", "utf8");

  const signMessage = (message) => {
    var signer = crypto.createSign("RSA-SHA256");
    signer.update(message);

    var sign = signer.sign(m_privateKey, "base64");
    console.log(sign);

    return sign
  };

  const verifySign = (message, signed) => {
    var verifier = crypto.createVerify("RSA-SHA256");
    verifier.update(message);

    var result = verifier.verify(m_publicKey, signed, "base64");
    console.log(result);//true
  };

  return {
    signMessage,
    verifySign,
  };
};

const my_obj = sha256WithRSA()

const signed = my_obj.signMessage("Hello, sha256 with rsa!")
my_obj.verifySign("Hello, sha256 with rsa!", signed)