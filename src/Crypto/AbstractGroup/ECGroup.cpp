
#include <cryptopp/nbtheory.h>

#include "ECElementData.hpp"
#include "ECGroup.hpp"

namespace Dissent {
namespace Crypto {
namespace AbstractGroup {

  ECGroup::ECGroup(Integer p, Integer q, Integer a, Integer b, Integer gx, Integer gy) :
      _curve(ToCryptoInt(p), ToCryptoInt(a), ToCryptoInt(b)),
      _q(q),
      _g(ToCryptoInt(gx), ToCryptoInt(gy)),
      _field_bytes(p.GetByteArray().count())
    {
      qDebug() << " p" << p.GetByteArray().toHex(); 
      qDebug() << " a" << a.GetByteArray().toHex(); 
      qDebug() << " b" << b.GetByteArray().toHex(); 
      qDebug() << "gx" << gx.GetByteArray().toHex(); 
      qDebug() << "gy" << gy.GetByteArray().toHex(); 

      Q_ASSERT(ToCryptoInt(p) == _curve.FieldSize());
    };


  QSharedPointer<ECGroup> ECGroup::ProductionFixed() 
  {
    // RFC 5903 - 256-bit curve
    const Integer p(QByteArray::fromHex("0xFFFFFFFF000000010000000000"
                                        "00000000000000FFFFFFFFFFFFFFFFFFFFFFFF"));
    const Integer q(QByteArray::fromHex("0xFFFFFFFF00000000FFFFFFFFFF"
                                        "FFFFFFBCE6FAADA7179E84F3B9CAC2FC632551"));

    const Integer a(-3L);
    const Integer b(QByteArray::fromHex("0x5AC635D8AA3A93E7B3EBBD5576"
                                        "9886BC651D06B0CC53B0F63BCE3C3E27D2604B"));

    const Integer gx(QByteArray::fromHex("0x6B17D1F2E12C4247F8BCE6E56"
                                         "3A440F277037D812DEB33A0F4A13945D898C296"));
    const Integer gy(QByteArray::fromHex("0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE3"
                                         "3576B315ECECBB6406837BF51F5"));

    return QSharedPointer<ECGroup>(new ECGroup(p, q, a, b, gx, gy));
  }

  Element ECGroup::Multiply(const Element &a, const Element &b) const
  {
    return Element(new ECElementData(_curve.Add(GetPoint(a), GetPoint(b))));
  }

  Element ECGroup::Exponentiate(const Element &a, const Integer &exp) const
  {
    return Element(new ECElementData(_curve.Multiply(ToCryptoInt(exp), GetPoint(a))));
  }
  
  Element ECGroup::CascadeExponentiate(const Element &a1, const Integer &e1,
      const Element &a2, const Integer &e2) const
  {
    // For some reason, this is 50% faster than Crypto++'s native
    // CascadeMultiply
    return Element(new ECElementData(_curve.Add(
            _curve.Multiply(ToCryptoInt(e1), GetPoint(a1)),
            _curve.Multiply(ToCryptoInt(e2), GetPoint(a2)))));
   
    /*
    return Element(new ECElementData(_curve.CascadeMultiply(
          ToCryptoInt(e1), GetPoint(a1),
          ToCryptoInt(e2), GetPoint(a2))));
    */
    
  }

  Element ECGroup::Inverse(const Element &a) const
  {
    return Element(new ECElementData(_curve.Inverse(GetPoint(a))));
  }
  
  QByteArray ECGroup::ElementToByteArray(const Element &a) const
  {
    const unsigned int nbytes = _curve.EncodedPointSize(false);
    QByteArray out(nbytes, 0);
    _curve.EncodePoint((unsigned char*)(out.data()), GetPoint(a), false);
    return out;
  }
  
  Element ECGroup::ElementFromByteArray(const QByteArray &bytes) const 
  { 
    CryptoPP::ECPPoint point;
    _curve.DecodePoint(point, 
        (const unsigned char*)(bytes.constData()), 
        bytes.count());
    return Element(new ECElementData(point));
  }

  bool ECGroup::IsElement(const Element &a) const 
  {
    return _curve.VerifyPoint(GetPoint(a));
  }

  bool ECGroup::IsIdentity(const Element &a) const 
  {
    return (a == GetIdentity());
  }

  Integer ECGroup::RandomExponent() const
  {
    return Integer::GetRandomInteger(1, GetOrder(), false); 
  }

  Element ECGroup::RandomElement() const
  {
    return Exponentiate(GetGenerator(), RandomExponent());
  }

  CryptoPP::ECPPoint ECGroup::GetPoint(const Element &e) const
  {
    return ECElementData::GetPoint(e.GetData());
  }

  Element ECGroup::EncodeBytes(const QByteArray &in) const
  {
    /*
    * See the article 
    *  "Encoding And Decoding  of  a Message in the 
    *  Implementation of Elliptic Curve Cryptography 
    *  using Koblitz’s Method" for details on how this works.
    * 
    * k == MessageSerializationParameter defines the percentage
    * chance that we won't be able to encode a given message
    * in a given elliptic curve point. The failure probability
    * is 2^(-k).
    *
    * We can store b = log_2(p/k) bytes in every 
    * elliptic curve point, where p is the security
    * parameter (prime size) of the elliptic curve.
    *
    * For p = 2^256, k = 256, b = 224 (minus 2 padding bytes)
    */

    if(in.count() > BytesPerElement()) {
      qFatal("Failed to serialize over-sized string");
    }

    // Holds the data to be encoded plus a leading and a trailing
    // 0xFF byte
    QByteArray data;
    data.append(0xff);
    data += in;
    data.append(0xff);

    // r is an encoding of the string in a big integer
    CryptoPP::Integer r(("0x"+data.toHex()).constData());

    qDebug() << "r" << Integer(new CppIntegerData(r)).GetByteArray().toHex();
    
    Q_ASSERT(r < _curve.FieldSize());

    Element point;
    CryptoPP::Integer x, y;
    for(int i=0; i<_k; i++) {
      // x = rk + i mod p
      x = ((r*_k)+i);

      Q_ASSERT(x < _curve.FieldSize());

      if(SolveForY(x, point)) {
        return point;
      } 
    }

    qFatal("Failed to find point");
    return Element(new ECElementData(CryptoPP::ECPPoint()));
  }
 
  bool ECGroup::DecodeBytes(const Element &a, QByteArray &out) const
  {
    // output value = floor( x/k )
    CryptoPP::Integer x = GetPoint(a).x;
   
    // x = floor(x/k)
    CryptoPP::Integer remainder, quotient;
    CryptoPP::Integer::Divide(remainder, quotient, x, CryptoPP::Integer(_k));

    Integer intdata(new CppIntegerData(quotient));

    QByteArray data = intdata.GetByteArray(); 

    if(data.count() < 2) {
      qWarning() << "Data is too short";
      return false;
    }

    const unsigned char c = 0xff;
    const unsigned char d0 = data[0];
    const unsigned char dlast = data[data.count()-1];
    if((d0 != c) || (dlast != c)) {
      qWarning() << "Data has improper padding";
      return false;
    }

    out = data.mid(1, data.count()-2);
    return true;
  }

  bool ECGroup::IsProbablyValid() const
  {
    qDebug() << IsElement(GetGenerator());
    qDebug() << IsIdentity(Exponentiate(GetGenerator(), GetOrder()));

    return IsElement(GetGenerator()) && 
      IsIdentity(Exponentiate(GetGenerator(), GetOrder())) &&
      CryptoPP::IsPrime(_curve.FieldSize()) &&
      CryptoPP::IsPrime(ToCryptoInt(GetOrder()));
  }

  QByteArray ECGroup::GetByteArray() const
  {
    QByteArray out;
    QDataStream stream(&out, QIODevice::WriteOnly);

    stream << FromCryptoInt(_curve.FieldSize()).GetByteArray() 
      << FromCryptoInt(_curve.GetA()).GetByteArray()
      << FromCryptoInt(_curve.GetB()).GetByteArray();

    return out;
  }

  bool ECGroup::SolveForY(const CryptoPP::Integer &x, Element &point) const
  {
    // y^2 = x^3 + ax + b (mod p)

    CryptoPP::ModularArithmetic arith(_curve.FieldSize());

    // tmp = x
    CryptoPP::Integer tmp = x;

    // tmp = x^2
    tmp = arith.Square(tmp);

    // tmp = x^2 + a
    tmp = arith.Add(tmp, _curve.GetA());

    // tmp = x (x^2 + a) == (x^3 + ax)
    tmp = arith.Multiply(tmp, x);

    // tmp = x^3 + ax + b
    tmp = arith.Add(tmp, _curve.GetB());
   
    // does there exist y such that (y^2 = x^3 + ax + b) mod p ?

    // jacobi symbol is 1 if tmp is a non-trivial 
    // quadratic residue mod p
    bool solved = (CryptoPP::Jacobi(tmp, _curve.FieldSize()) == 1);

    if(solved) {
      const CryptoPP::Integer y = CryptoPP::ModularSquareRoot(tmp, _curve.FieldSize());

      point = Element(new ECElementData(CryptoPP::ECPPoint(x, y)));
      Q_ASSERT(IsElement(point));
    }

    return solved;
  }

}
}
}
