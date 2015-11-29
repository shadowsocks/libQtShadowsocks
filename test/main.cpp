#include <QTest>
#include "address.t.h"

int main(int, char **)
{
    Address_T addr_t;
    QTest::qExec(&addr_t);

    return 0;
}
