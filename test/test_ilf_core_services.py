'''
test Ip4Services
'''

import sys
sys.path.insert(0, '..')
sys.path.insert(0, '.')

from jabs import ilf

def test_init():
    ips = ilf.Ip4Service()
    del ips  # to prevent unused var err msg
