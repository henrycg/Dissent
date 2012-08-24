
#include "PairingElementData.hpp"
#include "PairingGroup.hpp"

namespace Dissent {
namespace Crypto {
namespace AbstractGroup {
   const char PairingGroup::_param_bytes[] = "type a\n"
            "q 80446847579655582597444149989235076764876194923554360266341368662"
            "3305841804412818608112457890014205661401911491189163051225232968716"
            "794196786018682667008059\n"
            "h 60\n"
            "r 13407807929942597099574024998205846127479365820592393377723561443"
            "7217640300735469768018742981669034276900318581864860508537538828119"
            "46569946433644711116801\n"
            "exp2 512\n"
            "exp1 32\n"
            "sign1 -1\n"
            "sign0 1\n";

  const char PairingGroup::_order_bytes[] = 
            "0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
            "fffffffffffffffffffffffffffffffffffffffffffffffffffffff00000001";

  PairingGroup::PairingGroup() :
    _param_str(QByteArray(_param_bytes)),
    _pairing(_param_str.constData(), _param_str.count()),
    _order(Integer(QByteArray::fromHex(_order_bytes)))
  {
    Q_ASSERT(_pairing.isPairingPresent());

    _z_tmp = (mpz_t*)malloc(sizeof(*_z_tmp));
    Q_ASSERT(_z_tmp);
    mpz_init(*_z_tmp);
  };

  PairingGroup::~PairingGroup()
  {
    mpz_clear(*_z_tmp);
    free(_z_tmp);
  }

  Integer PairingGroup::RandomExponent() const
  {
    return Integer::GetRandomInteger(1, GetOrder(), false); 
  }
  
  Zr PairingGroup::IntegerToZr(const Integer &in) const
  { 
    const char *bytes = in.GetByteArray().toHex().constData();
    if(gmp_sscanf(bytes, "%Zx", *_z_tmp) != 1) {
      qDebug() << "Bad string" << bytes;
      qFatal("Could not convert integer");
    }

    Zr e(_pairing, *_z_tmp);
    Q_ASSERT(e.isElementPresent());
    return e; 
  }

}
}
}