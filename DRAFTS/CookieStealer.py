import requests
import json

class test(object):
    def __init__(self):
      self._debug = False
      self._http_debug = False
      self._https = True
      self._session = requests.session() # use single session for all requests
    
    def update_csrf(self):
        # Retrieve server csrf and update session's headers
        for cookie in self._session.cookies:
            if cookie.name == 'ccsrftoken':
                csrftoken = cookie.value[1:-1] # token stored as a list
                self._session.headers.update({'X-CSRFTOKEN': csrftoken})


    def login(self,host,username,password):
        self.host = host
        if self._https is True:
            self.url_prefix = 'https://' + self.host
        else:
            self.url_prefix = 'http://' + self.host
        url = self.url_prefix + '/logincheck'
        res = self._session.post(url,
                                data='username='+username+'&secretkey='+password,
                                verify = False)
        #self.dprint(res)

        # Update session's csrftoken
        self.update_csrf()

    
    def get(self, url):
        url = url
        res = self._session.get(url)
        return res.content
  
f = test()    
f.login(ip,username, password)