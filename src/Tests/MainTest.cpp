#include <time.h>
#include <botan/botan.h>

#include "DissentTest.hpp"

void FileExists(QString filename);
void FileDelete(QString filename);
void FilesExist();
void FilesDelete();

class DissentEnvironment : public testing::Environment {
 public:

   // Necessary for Botan crypto library to work
   DissentEnvironment() : init("thread_safe=true") {};
   Botan::LibraryInitializer init;
};

GTEST_API_ int main(int argc, char **argv)
{

  QCoreApplication qca(argc, argv);
//  CryptoFactory::GetInstance().SetThreading(CryptoFactory::MultiThreaded);
//  Dissent::Crypto::AsymmetricKey::DefaultKeySize = 512;
//  Dissent::Crypto::AsymmetricKey::DefaultKeySize = 512;
  Logging::UseFile("test.log");
  qDebug() << "Beginning tests";
  FilesExist();

  testing::AddGlobalTestEnvironment(new DissentEnvironment());
  testing::InitGoogleTest(&argc, argv);

  int res = RUN_ALL_TESTS();
  FilesDelete();
  return res;
}

void FilesExist()
{
  FileExists("dissent.ini");
  FileExists("private_key");
  FileExists("public_key");
}

void FilesDelete()
{
  FileDelete("dissent.ini");
  FileDelete("private_key");
  FileDelete("public_key");
}

void FileExists(QString filename)
{
  QFile file(filename);
  if(file.exists()) {
    qFatal("%s", QString(filename + " exists, move / delete and restart the test.").toUtf8().constData());
  }
}

void FileDelete(QString filename)
{
  QFile file(filename);
  file.remove();
}
