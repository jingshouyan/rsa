<?php
/**
 * Created by PhpStorm.
 * User: Administrator
 * Date: 2015/8/11
 * Time: 13:58
 */

namespace Jingshouyan\Rsa;


class Rsa
{
  protected $priKey;
  protected $pubKey;

  /**
   * 构造函数
   *
   * @param string $pubKeyStr 公钥BASE64格式字符串，不包含begin/end
   * @param string $priKeyStr 私钥BASE64格式字符串，不包含begin/end。非加密私钥
   * @param string $priKeyStyle 私钥格式，默认rsa，可选rsa，pkcs8
   * @throws \Exception
   */
  public function __construct($pubKeyStr = '', $priKeyStr = '', $priKeyStyle = 'rsa')
  {
    try {
      if ($pubKeyStr) {
        $this->setPubKey($pubKeyStr);
      }
      if ($priKeyStr) {
        $this->setPriKey($priKeyStr, $priKeyStyle);
      }
    } catch (\Exception $e) {
      //TODO: 异常处理
      throw $e;
    }
  }


  /**
   * 设置公钥
   *
   * @param　string $keyStr 公钥BASE64格式字符串，不包含begin/end
   * @return $this
   * @throws \Exception
   */
  public function setPubKey($keyStr)
  {
    try {
      $start = "-----BEGIN PUBLIC KEY-----\n";
      $keyStr = $this->keyFormat($keyStr);
      $end = "-----END PUBLIC KEY-----\n";
      $keyContent = $start . $keyStr . $end;
      $this->pubKey = openssl_get_publickey($keyContent);
      return $this;
    } catch (\Exception $e) {
      //TODO: 异常处理
      throw $e;
    }
  }

  /**
   * 设置私钥
   *
   * @param string $keyStr 私钥BASE64格式字符串，不包含begin/end。非加密私钥
   * @param string $keyStyle 私钥格式，默认rsa，可选rsa，pkcs8
   * @return $this
   * @throws \Exception
   */
  public function setPriKey($keyStr, $keyStyle = 'rsa')
  {
    try {
      if ($keyStyle === 'rsa') {
        $start = "-----BEGIN RSA PRIVATE KEY-----\n";
        $end = "-----END RSA PRIVATE KEY-----\n";
      } else {
        $start = "-----BEGIN PRIVATE KEY-----\n";
        $end = "-----END PRIVATE KEY-----\n";
      }
      $keyStr = $this->keyFormat($keyStr);
      $keyContent = $start . $keyStr . $end;
      $this->priKey = openssl_get_privatekey($keyContent);
      return $this;
    } catch (\Exception $e) {
      //TODO: 异常处理
      throw $e;
    }
  }

  /**
   * 生成签名
   *
   * @param string　$data 签名材料
   * @param string $code　签名编码（base64/hex/bin）
   * @return string 签名值
   */
  public function sign($data, $code = 'base64')
  {
    $ret = false;
    if (openssl_sign($data, $ret, $this->priKey, OPENSSL_ALGO_MD5)) {
      $ret = $this->_encode($ret, $code);
    }
    return $ret;
  }

  /**
   * 验证签名
   *
   * @param string　$data 签名材料
   * @param string　$sign 签名值
   * @param string　$code 签名编码（base64/hex/bin）
   * @return bool
   */
  public function verify($data, $sign, $code = 'base64')
  {
    $ret = false;
    $sign = $this->_decode($sign, $code);
    if ($sign !== false) {
      switch (openssl_verify($data, $sign, $this->pubKey, OPENSSL_ALGO_MD5)) {
        case 1:
          $ret = true;
          break;
        case 0:
        case -1:
        default:
          $ret = false;
      }
    }
    return $ret;
  }

  /**
   * 加密
   *
   * @param string　$data 明文
   * @param string　$code　密文编码（base64/hex/bin）
   * @param int　$padding 填充方式（貌似php有bug，所以目前仅支持OPENSSL_PKCS1_PADDING）
   * @return string 密文
   */
  public function encrypt($data, $code = 'base64', $padding = OPENSSL_PKCS1_PADDING)
  {
    $ret = false;
    if (!$this->_checkPadding($padding, 'en')) throw new \Exception('padding error');
    if (openssl_public_encrypt($data, $result, $this->pubKey, $padding)) {
      $ret = $this->_encode($result, $code);
    }
    return $ret;
  }

  /**
   * 解密
   *
   * @param string　$data 密文
   * @param string　$code 密文编码（base64/hex/bin）
   * @param int　$padding 填充方式（OPENSSL_PKCS1_PADDING / OPENSSL_NO_PADDING）
   * @param bool　$rev 是否翻转明文（When passing Microsoft CryptoAPI-generated RSA cyphertext, revert the bytes in the block）
   * @return string 明文
   */
  public function decrypt($data, $code = 'base64', $padding = OPENSSL_PKCS1_PADDING, $rev = false)
  {
    $ret = false;
    $data = $this->_decode($data, $code);
    if (!$this->_checkPadding($padding, 'de')) throw new \Exception('padding error');
    if ($data !== false) {
      if (openssl_private_decrypt($data, $result, $this->priKey, $padding)) {
        $ret = $rev ? rtrim(strrev($result), "\0") : '' . $result;
      }
    }
    return $ret;
  }


  // 私有方法

  /**
   * 检测填充类型
   * 加密只支持PKCS1_PADDING
   * 解密支持PKCS1_PADDING和NO_PADDING
   *
   * @param int　$padding 填充模式
   * @param string　$type 加密en/解密de
   * @return bool
   */
  private function _checkPadding($padding, $type)
  {
    if ($type == 'en') {
      switch ($padding) {
        case OPENSSL_PKCS1_PADDING:
          $ret = true;
          break;
        default:
          $ret = false;
      }
    } else {
      switch ($padding) {
        case OPENSSL_PKCS1_PADDING:
        case OPENSSL_NO_PADDING:
          $ret = true;
          break;
        default:
          $ret = false;
      }
    }
    return $ret;
  }

  private function _encode($data, $code)
  {
    switch (strtolower($code)) {
      case 'base64':
        $data = base64_encode('' . $data);
        break;
      case 'hex':
        $data = bin2hex($data);
        break;
      case 'bin':
      default:
    }
    return $data;
  }

  private function _decode($data, $code)
  {
    switch (strtolower($code)) {
      case 'base64':
        $data = base64_decode($data);
        break;
      case 'hex':
        $data = $this->_hex2bin($data);
        break;
      case 'bin':
      default:
    }
    return $data;
  }

  private function _hex2bin($hex = false)
  {
    $ret = $hex !== false && preg_match('/^[0-9a-fA-F]+$/i', $hex) ? pack("H*", $hex) : false;
    return $ret;
  }


  /**
   * 密钥格式整理
   *
   * @param string $keyStr 密钥BASE64格式字符串，不包含begin/end
   * @return string 格式化后的密钥字符串，64位字符一行
   */
  private function keyFormat($keyStr)
  {
    $keyStr = preg_replace('/\s/', '', $keyStr);
    return chunk_split($keyStr, 64, "\n");
  }
}