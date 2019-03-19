from os.path import dirname, join

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from ..backend import app, drop_db, install_dev_data


@pytest.fixture(scope='function')
def db_session(alembic_config):
    session = sessionmaker(bind=create_engine(app.config['DB']))()
    return session


@pytest.yield_fixture(scope='function')
def alembic_config():
    ini_location = join(dirname(__file__), '..', '..', 'alembic.ini')
    sqlalchemy_url = app.config['DB']
    config = Config(ini_location)
    config.set_main_option('sqlalchemy.url', sqlalchemy_url)
    command.upgrade(config, 'head')
    install_dev_data()
    yield config
    drop_db()


PRIVATE_KEY = (
    'LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQpNSUlFb3dJQkFBS0NBUUVBamI4M'
    'm5vbFIweVV4MTVMcVZLSGRnQWhMakhrNlJvL3BkZmVKU1hkTmVGQTJJUUZBCjNPOENJSz'
    'Y5RVBhQ3lJaEIxOTRUNm5hNjRFYU5BRlpVc0MrY3hWUjM4VFNGU0VzeVI1N2FGV29GMHl'
    'YZDhsVzEKQXgza3M2Y1hqVjk3UGMwK1ZjNFRYWHViaEpxakVET2dhR0JYcnlCaHY3TXZh'
    'YUxIRngwdTMwblZ5LzR5RkFlbwp5cUErUjZKWnhkalRlRUVWZDdsMi9scHUyM1N6ZU9SK'
    '1dSTjdWbHpGNFVSRFVzMjFoS0pPV3gwSFJjQTZ5UUwvCkFqczVSaUJkODhrbC95QXJUWE'
    'FxN0RDMkY1NWpvSnhJQjFVc1V3T0p0ZzVnQ3lkMERPQ2svQ05KLysxSHNMWlIKejF6cVp'
    'TMUZObzhXRUxDU3l2dWRuc0dDdTlyLzU0WU1VM2o1RHdJREFRQUJBb0lCQUE3K2RaUWlt'
    'WDI0MXdOagpQcGR5UWVCN3dDWWRZcjA1RnV5TUlVRWN0aHl1ZTNOVlV4dXJ5ckZUV3B1V'
    'FAvVmZlSHVSdWRDWSs1Nml4K0tMCnYweWQxTHNJK3VFUWViTFNoWUNPL0ttOE85NkFpSE'
    'JNZ2FmUlB6S0R6OWw4Q3FqWWI2b2E4UEI0RlZUYkdMbXIKaEdIV0l5QmEwQXc3czUyOGd'
    'zdmVvZWtyd2NwZ3NuRjlBNE1lYnNWcjh5a3pteG1yOFp4aDV2TEYxMnVnWDc1RApWZUdN'
    'NER2SmJnM05mbWFteXF3SWFzV0xEcisrczFQUXFRQlJFZ0tJZCs5emxzcXFjd1RmeEkzM'
    '3R2aE1Ma3owCjVTRldZUitEVXgvcWo2bWFjNHNhVWJSWmFGaVhIaXB4K0hxV3kxeTZBaG'
    'krR2pWZFNVaGtodVgxRjg4VEJhdzEKSzh0SmtQVUNnWUVBdVZvOFdrYXVOU2l6UGl0RVp'
    'kYjJOSnppMFB6dnBaQjBWc1lNa3BFb2hnWXo3eXdHTUViMQppOFZKWEhkYk9qVWpSMHNJ'
    'Rm1ObTJhc1FKQzJLRG9RUWpSWHlNSDh3QWRNMXNzVHlVNGFocEhjMWtrbE80cFVYCmtZZ'
    'nM2cVhRY1lTNFNrTGRPYUhQcnFwSjRaSmdMa3RNM0c4VUd1Y1Z3WHlOaVZVTG9DTEQ4Zk'
    '1DZ1lFQXc4WXEKbmRscWpYbDBJdHEvL2RjWUlTYnRXTDhva1hENGNpcTV5R2laTUxSOFR'
    'QOG1zUmMyQUozZWprd3h3U1VFZE0vTApJWm0yWlF4MzlNdjRKUjJ6Q0s5d3gzNTZYVHFH'
    'ZUNIZjFFR2xyekM5WVlidzg1ck0vRGdKZ1BiT2RBbmIvRFZKCjJ2eWhrRS9Ob0lIUW1DT'
    'mFET1JieU55aXZCYjNMRVA1NEx3clIzVUNnWUJrSE84WU83RUFtWGtuRFN1bWJoTVIKbS'
    'tPT3llK08xNVZmQVIzdFZHWTA3Y2pEV0Y0SFdXeHJFQ1p0d1RJUElJQnJrNFZNd21mZER'
    'kNXNEQVRUamxWNgpQdTVQYjRNNG1TSVo2dktRVnRtY0FaOTM0Z3l2cWFQUFFVR2dBK3V3'
    'Uk9WZGh2d0Nrdm1mOSs1cjNpb0JGejd1Cm1UaWN4MUFpNytscTBmcXpoZE9jTFFLQmdRQ'
    '0tnd3BqNUErZlNPOENPZ0xjZGZKOGdpNHJQQlJYMHJYMUVJV2gKWlYvOU5iVThSTW43UV'
    'pEVG50NTNqekVrbGl3dytWT2Uwa0paL0JoaSttejIxYXgxMktyU2VvbllyQyszanovdAp'
    '6UVNNanM5dTBTcHBNSDBYZGc1RFVGdUJmZmhHMk8wSUl2V3NSTW9YWmNGUDRyTXpxOTNF'
    'bjFZRC9idWpkZlMxCkxHenlnUUtCZ0QrVWxwVmlRMTF0cDdjRzJjejEyQ2xjQlpSVi9zY'
    'VJJemNjTDE5UFJleWRDcmYxLzZOY2tKSjkKTlhXVnQvZVN0TEpkTnlDM2VaSjE5QlNhbj'
    'lZbFZYdDZZdzRuTERKZytWSVY5VFZPdlpLRy9xbU94Qmd3b2Nydwp0NldFT09hU0Exd1E'
    '3ODErY3o1bnNzcStWMXoyK240dGd5TEU0RmN3TldpUE1pd1BiNk9xCi0tLS0tRU5EIFJT'
    'QSBQUklWQVRFIEtFWS0tLS0t'
)
