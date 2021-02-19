from bs4 import BeautifulSoup,sys
import urllib3
#warna
red = '\33[31;1m'
white = '\33[37;1m'
green= '\33[32;1m'
cyan='\33[0;36m'
#remove duplicate
http = urllib3.PoolManager()
list = open('hasil.txt','r')
sv_vuln = open('vuln.txt','a')
print('Checking version....\n')
for line in list:
  ip = line.replace('\n','').split('|')
  try:
    response = http.request('GET', ip[0],timeout=5)
    soup = BeautifulSoup(response.data,'html.parser')
    version = soup.find('h1').text
    vuln = ['RouterOS v6.30.1','RouterOS v6.30.2','RouterOS v6.30.3','RouterOS v6.30.4','RouterOS v6.30.5',' RouterOS v6.30.6','RouterOS v6.30.7','RouterOS v6.30.8','RouterOS v6.30.9','RouterOS v6.31.1','RouterOS v6.31.2','RouterOS v6.31.3','RouterOS v6.31.4','RouterOS v6.31.5',' RouterOS v6.31.6','RouterOS v6.31.7','RouterOS v6.31.8','RouterOS v6.31.9','RouterOS v6.32.1','RouterOS v6.32.2','RouterOS v6.32.3','RouterOS v6.32.4','RouterOS v6.32.5',' RouterOS v6.32.6','RouterOS v6.32.7','RouterOS v6.32.8','RouterOS v6.32.9','RouterOS v6.33.1','RouterOS v6.33.2','RouterOS v6.33.3','RouterOS v6.33.4','RouterOS v6.33.5',' RouterOS v6.33.6','RouterOS v6.33.7','RouterOS v6.33.8','RouterOS v6.33.9','RouterOS v6.34.1','RouterOS v6.34.2','RouterOS v6.34.3','RouterOS v6.34.4','RouterOS v6.34.5',' RouterOS v6.34.6','RouterOS v6.34.7','RouterOS v6.34.8','RouterOS v6.34.9','RouterOS v6.35.1','RouterOS v6.35.2','RouterOS v6.35.3','RouterOS v6.35.4','RouterOS v6.35.5',' RouterOS v6.35.6','RouterOS v6.35.7','RouterOS v6.35.8','RouterOS v6.35.9','RouterOS v6.36.1','RouterOS v6.36.2','RouterOS v6.36.3','RouterOS v6.36.4','RouterOS v6.36.5',' RouterOS v6.36.6','RouterOS v6.36.7','RouterOS v6.36.8','RouterOS v6.36.9','RouterOS v6.37.1','RouterOS v6.37.2','RouterOS v6.37.3','RouterOS v6.37.4','RouterOS v6.37.5',' RouterOS v6.37.6','RouterOS v6.37.7','RouterOS v6.37.8','RouterOS v6.37.9','RouterOS v6.38.1','RouterOS v6.38.2','RouterOS v6.38.3','RouterOS v6.38.4','RouterOS v6.38.5',' RouterOS v6.38.6','RouterOS v6.38.7','RouterOS v6.38.8','RouterOS v6.38.9','RouterOS v6.39.1','RouterOS v6.39.2','RouterOS v6.39.3','RouterOS v6.39.4','RouterOS v6.39.5',' RouterOS v6.39.6','RouterOS v6.39.7','RouterOS v6.39.8','RouterOS v6.39.9','RouterOS v6.40.1','RouterOS v6.40.2','RouterOS v6.40.3','RouterOS v6.40.4','RouterOS v6.40.5','RouterOS v6.40.6','RouterOS v6.40.7','RouterOS v6.29','RouterOS v6.30','RouterOS v6.31','RouterOS v6.32','RouterOS v6.33',' RouterOS v6.34','RouterOS v6.35','RouterOS v6.36','RouterOS v6.37','RouterOS v6.38','RouterOS v6.39','RouterOS v6.40','RouterOS v6.41','RouterOS v6.42','RouterOS v6.29rc1','RouterOS v6.29rc2','RouterOS v6.29rc3','RouterOS v6.30rc1','RouterOS v6.30rc2','RouterOS v6.30rc3','RouterOS v6.31rc1','RouterOS v6.31rc2','RouterOS v6.31rc3','RouterOS v6.32rc1','RouterOS v6.32rc2','RouterOS v6.32rc3','RouterOS v6.33rc1','RouterOS v6.33rc2','RouterOS v6.33rc3','RouterOS v6.34rc1','RouterOS v6.34rc2','RouterOS v6.34rc3','RouterOS v6.35rc1','RouterOS v6.35rc2','RouterOS v6.35rc3','RouterOS v6.36rc1','RouterOS v6.36rc2','RouterOS v6.36rc3','RouterOS v6.37rc1','RouterOS v6.37rc2','RouterOS v6.37rc3','RouterOS v6.38rc1','RouterOS v6.38rc2','RouterOS v6.38rc3','RouterOS v6.39rc1','RouterOS v6.39rc2','RouterOS v6.39rc3']

    if version in vuln:
      print('>>IP : %s%s%s|ISP %s%s%s|%s%s%s| is %svuln!!%s'%(cyan,ip[0],white,cyan,ip[1],white,cyan,version,white,green,white))
      sv_vuln.write('%s|ISP %s\n'%(ip[0],ip[1]))
    elif not 'RouterOS' in version:
      print('%s is not RouterOS'%(ip[0]))
      pass
    else:
       print('>>IP : %s%s%s|ISP %s%s%s|%s%s%s| is %s not vuln!!%s'%(cyan,ip[0],white,cyan,ip[1],white,cyan,version,white,red,white))

  except (ConnectionResetError, urllib3.exceptions.MaxRetryError) as e:
    print('%s%s%s'%(red,e,white))
    continue
  except KeyboardInterrupt:
    exit('\nKeyboardInterrupt exiting....')
  except AttributeError:
    pass
  continue
