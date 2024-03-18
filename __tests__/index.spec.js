import { expect, test, vi } from 'vitest'
import { AuthStatusCode, AuthenticatedUser, SignInStatusCode, SimpleOTP } from '../index'
import http, { AxiosError } from 'axios'

test('new SimpleOTP() throws when the siteID is invalid', () => {
  const invalidFuncs = [() => new SimpleOTP(), () => new SimpleOTP(''), () => new SimpleOTP(1), () => new SimpleOTP(null), () => new SimpleOTP(undefined)]
  for (let invalidFunc of invalidFuncs) {
    expect(invalidFunc).toThrow()
  }
})

test('new SimpleOTP() throws when the apiURL is invalid', () => {
  const invalidFuncs = [() => new SimpleOTP('site', 'notaurl'), () => new SimpleOTP('site', '1'), () => new SimpleOTP('site', 1)]
  for (let invalidFunc of invalidFuncs) {
    expect(invalidFunc).toThrow()
  }
})

test('new SimpleOTP() initializes the constructor params and the user key when the params are valid with a default apiURL', () => {
  const simpleOTP = new SimpleOTP('mocksiteid')

  expect(simpleOTP).toBeTruthy()
  expect(simpleOTP.apiURL).toBe('https://api.simpleotp.com')
  expect(simpleOTP.simpleOTPUserKey).toBe('simpleotp_user:mocksiteid')
})

test('new SimpleOTP() initializes the constructor params and the user key when the params are valid with a custom apiURL', () => {
  const simpleOTP = new SimpleOTP('mocksiteid', 'https://google.com')

  expect(simpleOTP).toBeTruthy()
  expect(simpleOTP.apiURL).toBe('https://google.com')
  expect(simpleOTP.simpleOTPUserKey).toBe('simpleotp_user:mocksiteid')
})

test('signIn() throws when the email is invalid', async () => {
  const simpleOTP = new SimpleOTP('mocksiteid')
  expect(async () => await simpleOTP.signIn()).rejects.toThrow()
  expect(async () => await simpleOTP.signIn(2)).rejects.toThrow()
  expect(async () => await simpleOTP.signIn('')).rejects.toThrow()
})

test('signIn() returns the code and message when the http call succeeds', async () => {
  const simpleOTP = new SimpleOTP('mocksiteid')
  const mockPost = vi.spyOn(http, 'post')
  mockPost.mockImplementation(() => {
    return { data: { code: 'ok', message: 'all good' } }
  })

  const resp = await simpleOTP.signIn('support@simpleotp.com')
  expect(resp.code).toBe('ok')
  expect(resp.message).toBe('all good')
})

test('signIn() returns the code and message when the http call fails', async () => {
  const simpleOTP = new SimpleOTP('mocksiteid')
  const mockPost = vi.spyOn(http, 'post')
  mockPost.mockImplementation(() => {
    throw { response: { data: { code: 'uh_oh', message: 'oh noes' } } }
  })

  const resp = await simpleOTP.signIn('support@simpleotp.com')
  expect(resp.code).toBe('uh_oh')
  expect(resp.message).toBe('oh noes')
})

test('signIn() returns a networking error when the http call does not have a response prop', async () => {
  const simpleOTP = new SimpleOTP('mocksiteid')
  const mockPost = vi.spyOn(http, 'post')
  mockPost.mockImplementation(() => {
    throw { response2: { data: { code: 'uh_oh', message: 'oh noes' } } }
  })

  const resp = await simpleOTP.signIn('support@simpleotp.com')
  expect(resp.code).toBe(SignInStatusCode.NetworkingError.description)
  expect(resp.message).toBe('Could not connect to the server. Try again in a few moments.')
})

test('authWithWebAuthnCredentials() throws when the browser doesn\'t support WebAuthn', async() => {
  const simpleOTP = new SimpleOTP('mocksiteid')
  window.PublicKeyCredential = null

  expect(async () => await simpleOTP.authWithWebAuthnCredentials('billg@microsoft.com')).rejects.toThrow()
})

test('registerWebAuthn() throws when the browser doesn\'t support WebAuthn', async() => {
  const simpleOTP = new SimpleOTP('mocksiteid')
  window.PublicKeyCredential = null

  expect(async () => await simpleOTP.registerWebAuthnCredentials('billg@microsoft.com')).rejects.toThrow()
})

test('authWithWebAuthnCredentials() throws when the email is invalid', async() => {
  const simpleOTP = new SimpleOTP('mocksiteid')
  window.PublicKeyCredential = {}
  navigator.credentials = { get: () => {}, create: () => {} }

  expect(async () => await simpleOTP.authWithWebAuthnCredentials(null)).rejects.toThrow()
  expect(async () => await simpleOTP.authWithWebAuthnCredentials(2)).rejects.toThrow()
})

test('authWithWebAuthnCredentials() returns the a networking error when the response is missing for start login', async() => {
  const simpleOTP = new SimpleOTP('mocksiteid')
  const mockPost = vi.spyOn(http, 'post')
  mockPost.mockImplementation((url) => {
    if(url.indexOf('start') >= 0) {
      throw new Error('something blew up')
    }
    return {
      data: { data: { id: 'someid', email: 'billg@microsoft.com', token: 'reallysecuretoken' } }
    }
  })

  window.PublicKeyCredential = {}
  navigator.credentials = { 
    create: () => {
      throw Error('should not call create here')
    },
    get: () => {
      throw Error('should not call get here')
    }
  }

  const authResponse = await simpleOTP.authWithWebAuthnCredentials('billg@microsoft.com')
  expect(authResponse).toBeTruthy()
  expect(authResponse.code).toBe('networking_error')
  expect(authResponse.data).toBeFalsy()

  expect(simpleOTP.isAuthenticated()).toBe(false)
})

test('authWithWebAuthnCredentials() returns the api error code when one is returned for start login', async() => {
  const simpleOTP = new SimpleOTP('mocksiteid')
  const mockPost = vi.spyOn(http, 'post')
  mockPost.mockImplementation((url) => {
    if(url.indexOf('start') >= 0) {
      throw { 
        response: { data: { code: 'wehaveaproblem', message: 'somemsg' } }
      }
    }
    return {
      data: { data: { id: 'someid', email: 'billg@microsoft.com', token: 'reallysecuretoken' } }
    }
  })

  window.PublicKeyCredential = {}
  navigator.credentials = { 
    create: () => {
      throw Error('should not call create here')
    },
    get: () => {
      throw Error('should not call get here')
    }
  }

  const authResponse = await simpleOTP.authWithWebAuthnCredentials('billg@microsoft.com')
  expect(authResponse).toBeTruthy()
  expect(authResponse.code).toBe('wehaveaproblem')
  expect(authResponse.message).toBe('somemsg')
  expect(authResponse.data).toBeFalsy()

  expect(simpleOTP.isAuthenticated()).toBe(false)
})

test('authWithWebAuthnCredentials() returns a networking error when the response is missing for finish login', async() => {
  const simpleOTP = new SimpleOTP('mocksiteid')
  const mockPost = vi.spyOn(http, 'post')
  mockPost.mockImplementation((url) => {
    if(url.indexOf('start') >= 0) {
      return { 
        data: { publicKey: { challenge: 'somechal' } },
        headers: { get: () => { return 'ayy' } }
      }
    }
    throw new Error('somefinisherror')
  })

  window.PublicKeyCredential = {}
  navigator.credentials = { 
    create: () => {
      throw Error('should not call create here')
    },
    get: () => {
      return {
        id: 'somecred',
        rawId: new ArrayBuffer(1),
        response: {
          authenticatorData: new ArrayBuffer(2),
          clientDataJSON: new ArrayBuffer(3),
          signature: new ArrayBuffer(4),
          userHandle: new ArrayBuffer(5)
        },
        type: 'cooltype',
        authenticatorAttachment: 'reallyattached',
        getClientExtensionResults: () => { return {} }
      }
    }
  }

  const authResponse = await simpleOTP.authWithWebAuthnCredentials('billg@microsoft.com')
  expect(authResponse).toBeTruthy()
  expect(authResponse.code).toBe('networking_error')
  expect(authResponse.data).toBeFalsy()

  expect(simpleOTP.isAuthenticated()).toBe(false)
})

test('registerWebAuthnCredentials() returns the api error code when one is returned for finish register', async() => {
  const simpleOTP = new SimpleOTP('mocksiteid')
  const mockPost = vi.spyOn(http, 'post')
  mockPost.mockImplementation((url) => {
    if(url.indexOf('start') >= 0) {
      return { 
        data: { publicKey: { challenge: 'somechal', user: { id: '1'} } },
        headers: { get: () => { return 'ayy' } }
      }
    }
    throw {
      response: { data: { code: 'finisherrcode', message: 'somemsg2' } }
    }
  })

  const mockGetUser = vi.spyOn(simpleOTP, 'getUser')
  mockGetUser.mockImplementation(() => {
    return new AuthenticatedUser('id', 'email@site.com', 'tok')
  })

  window.PublicKeyCredential = {}
  navigator.credentials = { 
    create: () => {
      return {
        id: 'somecred',
        rawId: new ArrayBuffer(1),
        response: {
          authenticatorData: new ArrayBuffer(2),
          clientDataJSON: new ArrayBuffer(3),
        },
        type: 'cooltype',
        authenticatorAttachment: 'reallyattached',
        getClientExtensionResults: () => { return {} }
      }
    },
    get: () => {
      throw Error('should not call get here')
    }
  }

  const authResponse = await simpleOTP.registerWebAuthnCredentials('billg@microsoft.com')
  expect(authResponse).toBeTruthy()
  expect(authResponse.code).toBe('finisherrcode')
  expect(authResponse.message).toBe('somemsg2')
  expect(authResponse.data).toBeFalsy()

  expect(simpleOTP.isAuthenticated()).toBe(false)
})

test('authWithWebAuthnCredentials() returns the api error code when one is returned for finish login', async() => {
  const simpleOTP = new SimpleOTP('mocksiteid')
  const mockPost = vi.spyOn(http, 'post')
  mockPost.mockImplementation((url) => {
    if(url.indexOf('start') >= 0) {
      return { 
        data: { publicKey: { challenge: 'somechal' } },
        headers: { get: () => { return 'ayy' } }
      }
    }
    throw {
      response: { data: { code: 'finisherrcode', message: 'somemsg2' } }
    }
  })

  window.PublicKeyCredential = {}
  navigator.credentials = { 
    create: () => {
      throw Error('should not call create here')
    },
    get: () => {
      return {
        id: 'somecred',
        rawId: new ArrayBuffer(1),
        response: {
          authenticatorData: new ArrayBuffer(2),
          clientDataJSON: new ArrayBuffer(3),
          signature: new ArrayBuffer(4),
          userHandle: new ArrayBuffer(5)
        },
        type: 'cooltype',
        authenticatorAttachment: 'reallyattached',
        getClientExtensionResults: () => { return {} }
      }
    }
  }

  const authResponse = await simpleOTP.authWithWebAuthnCredentials('billg@microsoft.com')
  expect(authResponse).toBeTruthy()
  expect(authResponse.code).toBe('finisherrcode')
  expect(authResponse.message).toBe('somemsg2')
  expect(authResponse.data).toBeFalsy()

  expect(simpleOTP.isAuthenticated()).toBe(false)
})

test('authWithWebAuthnCredentials() returns an internal credential error when credentials get throws an unexpected error', async() => {
  const simpleOTP = new SimpleOTP('mocksiteid')
  const mockPost = vi.spyOn(http, 'post')
  mockPost.mockImplementation((url) => {
    if(url.indexOf('start') >= 0) {
      return { 
        data: { publicKey: { challenge: 'somechal' } },
        headers: { 
          get: (name) => {
            if (name === 'X-Simple-OTP-Web-Authn-Session-ID') {
              return 'sesh'
            }
            throw Error('unexpected header requested')
          }
        }
      }
    }
    return {
      data: { data: { id: 'someid', email: 'billg@microsoft.com', token: 'reallysecuretoken' } }
    }
  })

  window.PublicKeyCredential = {}
  navigator.credentials = { 
    create: () => {
      throw Error('should not call create here')
    },
    get: () => {
      throw {
        name: 'SomeOtherError'
      }
    }
  }

  const authResponse = await simpleOTP.authWithWebAuthnCredentials('billg@microsoft.com')
  expect(authResponse).toBeTruthy()
  expect(authResponse.code).toBe('internal_credential_error')

  expect(simpleOTP.isAuthenticated()).toBe(false)
})

test('authWithWebAuthnCredentials() returns a credential not selected error when the user cancels the dialog', async() => {
  const simpleOTP = new SimpleOTP('mocksiteid')
  const mockPost = vi.spyOn(http, 'post')
  mockPost.mockImplementation((url) => {
    if(url.indexOf('start') >= 0) {
      return { 
        data: { publicKey: { challenge: 'somechal' } },
        headers: { 
          get: (name) => {
            if (name === 'X-Simple-OTP-Web-Authn-Session-ID') {
              return 'sesh'
            }
            throw Error('unexpected header requested')
          }
        }
      }
    }
    return {
      data: { data: { id: 'someid', email: 'billg@microsoft.com', token: 'reallysecuretoken' } }
    }
  })

  window.PublicKeyCredential = {}
  navigator.credentials = { 
    create: () => {
      throw Error('should not call create here')
    },
    get: () => {
      throw {
        name: 'NotAllowedError'
      }
    }
  }

  const authResponse = await simpleOTP.authWithWebAuthnCredentials('billg@microsoft.com')
  expect(authResponse).toBeTruthy()
  expect(authResponse.code).toBe('credential_not_selected')

  expect(simpleOTP.isAuthenticated()).toBe(false)
})

test('registerWebAuthnCredentials() throws an error when the user is not authenticated', async() => {
  const simpleOTP = new SimpleOTP('mocksiteid')
  const mockPost = vi.spyOn(http, 'post') 
  mockPost.mockImplementation((url) => {
    if(url.indexOf('start') >= 0) {
      return { 
        data: { publicKey: { challenge: 'somechal', user: { id: 'id' } } },
        headers: { 
          get: (name) => {
            if (name === 'X-Simple-OTP-Web-Authn-Session-ID') {
              return 'sesh'
            }
            throw Error('unexpected header requested')
          }
        }
      }
    }
    return {
      data: { code: 'ok' }
    }
  })

  window.PublicKeyCredential = {}
  navigator.credentials = { 
    create: () => {
      return {
        id: 'somecred',
        rawId: new ArrayBuffer(1),
        response: {
          attestationObject: new ArrayBuffer(2),
          clientDataJSON: new ArrayBuffer(3),
        },
        type: 'cooltype',
        authenticatorAttachment: 'reallyattached',
        getClientExtensionResults: () => { return {} }
      }
    },
    get: () => {
      throw Error('should not call get here')
    }
  }

  expect(async () => await simpleOTP.registerWebAuthnCredentials('someunautheduser@mail.com')).rejects.toThrow() 
})

test('registerWebAuthnCredentials() returns internal credential error when an unexpected error happens during navigator.credentials.create()', async() => {
  const simpleOTP = new SimpleOTP('mocksiteid')
  const mockPost = vi.spyOn(http, 'post')
  mockPost.mockImplementation((url) => {
    if(url.indexOf('start') >= 0) {
      return { 
        data: { publicKey: { challenge: 'somechal', user: { id: 'id' } } },
        headers: { 
          get: (name) => {
            if (name === 'X-Simple-OTP-Web-Authn-Session-ID') {
              return 'sesh'
            }
            throw Error('unexpected header requested')
          }
        }
      }
    }
    return {
      data: { code: 'ok' }
    }
  })

  const mockGetUser = vi.spyOn(simpleOTP, 'getUser')
  mockGetUser.mockImplementation(() => {
    return new AuthenticatedUser('id', 'email@site.com', 'tok')
  })

  window.PublicKeyCredential = {}
  navigator.credentials = { 
    create: () => {
      throw { name: 'SomeOtherError' }
    },
    get: () => {
      throw Error('should not call get here')
    }
  }

  const authResponse = await simpleOTP.registerWebAuthnCredentials()
  expect(authResponse).toBeTruthy()
  expect(authResponse.code).toBe('internal_credential_error')
})

test('registerWebAuthnCredentials() returns credential not selected when the user cancels the dialog', async() => {
  const simpleOTP = new SimpleOTP('mocksiteid')
  const mockPost = vi.spyOn(http, 'post')
  mockPost.mockImplementation((url) => {
    if(url.indexOf('start') >= 0) {
      return { 
        data: { publicKey: { challenge: 'somechal', user: { id: 'id' } } },
        headers: { 
          get: (name) => {
            if (name === 'X-Simple-OTP-Web-Authn-Session-ID') {
              return 'sesh'
            }
            throw Error('unexpected header requested')
          }
        }
      }
    }
    return {
      data: { code: 'ok' }
    }
  })

  const mockGetUser = vi.spyOn(simpleOTP, 'getUser')
  mockGetUser.mockImplementation(() => {
    return new AuthenticatedUser('id', 'email@site.com', 'tok')
  })

  window.PublicKeyCredential = {}
  navigator.credentials = { 
    create: () => {
      throw { name: 'NotAllowedError' }
    },
    get: () => {
      throw Error('should not call get here')
    }
  }

  const authResponse = await simpleOTP.registerWebAuthnCredentials()
  expect(authResponse).toBeTruthy()
  expect(authResponse.code).toBe('credential_not_selected')
})

test('registerWebAuthnCredentials() returns a networking error when the error response is missing for finish', async() => {
  const simpleOTP = new SimpleOTP('mocksiteid')
  const mockPost = vi.spyOn(http, 'post')
  mockPost.mockImplementation((url) => {
    if(url.indexOf('start') >= 0) {
      return { 
        data: { publicKey: { challenge: 'somechal', user: { id: 'id' } } },
        headers: { 
          get: (name) => {
            if (name === 'X-Simple-OTP-Web-Authn-Session-ID') {
              return 'sesh'
            }
            throw Error('unexpected header requested')
          }
        }
      }
    }
    throw Error('somethingwentwrong')
  })

  const mockGetUser = vi.spyOn(simpleOTP, 'getUser')
  mockGetUser.mockImplementation(() => {
    return new AuthenticatedUser('id', 'email@site.com', 'tok')
  })

  window.PublicKeyCredential = {}
  navigator.credentials = { 
    create: () => {
      return {
        id: 'somecred',
        rawId: new ArrayBuffer(1),
        response: {
          attestationObject: new ArrayBuffer(2),
          clientDataJSON: new ArrayBuffer(3),
        },
        type: 'cooltype',
        authenticatorAttachment: 'reallyattached',
        getClientExtensionResults: () => { return {} }
      }
    },
    get: () => {
      throw Error('should not call get here')
    }
  }

  const authResponse = await simpleOTP.registerWebAuthnCredentials()
  expect(authResponse).toBeTruthy()
  expect(authResponse.code).toBe('networking_error')
})

test('registerWebAuthnCredentials() returns networking error when the error response is missing from start', async() => {
  const simpleOTP = new SimpleOTP('mocksiteid')
  const mockPost = vi.spyOn(http, 'post')
  mockPost.mockImplementation((url) => {
    if(url.indexOf('start') >= 0) {
      throw new Error('somethingwentwrong')
    }
    return {
      data: { code: 'ok' }
    }
  })

  const mockGetUser = vi.spyOn(simpleOTP, 'getUser')
  mockGetUser.mockImplementation(() => {
    return new AuthenticatedUser('id', 'email@site.com', 'tok')
  })

  window.PublicKeyCredential = {}
  navigator.credentials = { 
    create: () => {
      return {
        id: 'somecred',
        rawId: new ArrayBuffer(1),
        response: {
          attestationObject: new ArrayBuffer(2),
          clientDataJSON: new ArrayBuffer(3),
        },
        type: 'cooltype',
        authenticatorAttachment: 'reallyattached',
        getClientExtensionResults: () => { return {} }
      }
    },
    get: () => {
      throw Error('should not call get here')
    }
  }

  const authResponse = await simpleOTP.registerWebAuthnCredentials()
  expect(authResponse).toBeTruthy()
  expect(authResponse.code).toBe('networking_error')
})

test('registerWebAuthnCredentials() returns the api error when the error response is defined for start', async() => {
  const simpleOTP = new SimpleOTP('mocksiteid')
  const mockPost = vi.spyOn(http, 'post')
  mockPost.mockImplementation((url) => {
    if(url.indexOf('start') >= 0) {
      throw {
        response: { 
          data: { code: 'apierror' },
        }
      }
    }
    return {
      data: { code: 'ok' }
    }
  })

  const mockGetUser = vi.spyOn(simpleOTP, 'getUser')
  mockGetUser.mockImplementation(() => {
    return new AuthenticatedUser('id', 'email@site.com', 'tok')
  })

  window.PublicKeyCredential = {}
  navigator.credentials = { 
    create: () => {
      return {
        id: 'somecred',
        rawId: new ArrayBuffer(1),
        response: {
          attestationObject: new ArrayBuffer(2),
          clientDataJSON: new ArrayBuffer(3),
        },
        type: 'cooltype',
        authenticatorAttachment: 'reallyattached',
        getClientExtensionResults: () => { return {} }
      }
    },
    get: () => {
      throw Error('should not call get here')
    }
  }

  const authResponse = await simpleOTP.registerWebAuthnCredentials()
  expect(authResponse).toBeTruthy()
  expect(authResponse.code).toBe('apierror')
})

test('registerWebAuthnCredentials() sends the user\'s selected credentials to the server when they select valid credentials', async() => {
  const simpleOTP = new SimpleOTP('mocksiteid')
  const mockPost = vi.spyOn(http, 'post')
  mockPost.mockImplementation((url) => {
    if(url.indexOf('start') >= 0) {
      return { 
        data: { publicKey: { challenge: 'somechal', user: { id: 'id' } } },
        headers: { 
          get: (name) => {
            if (name === 'X-Simple-OTP-Web-Authn-Session-ID') {
              return 'sesh'
            }
            throw Error('unexpected header requested')
          }
        }
      }
    }
    return {
      data: { code: 'ok' }
    }
  })

  const mockGetUser = vi.spyOn(simpleOTP, 'getUser')
  mockGetUser.mockImplementation(() => {
    return new AuthenticatedUser('id', 'email@site.com', 'tok')
  })

  window.PublicKeyCredential = {}
  navigator.credentials = { 
    create: () => {
      return {
        id: 'somecred',
        rawId: new ArrayBuffer(1),
        response: {
          attestationObject: new ArrayBuffer(2),
          clientDataJSON: new ArrayBuffer(3),
        },
        type: 'cooltype',
        authenticatorAttachment: 'reallyattached',
        getClientExtensionResults: () => { return {} }
      }
    },
    get: () => {
      throw Error('should not call get here')
    }
  }

  const authResponse = await simpleOTP.registerWebAuthnCredentials()
  expect(authResponse).toBeTruthy()
  expect(authResponse.code).toBe('ok')
})

test('authWithWebAuthnCredentials() updates localStorage with the user details when the http call succeeds', async() => {
  const simpleOTP = new SimpleOTP('mocksiteid')
  const mockPost = vi.spyOn(http, 'post')
  mockPost.mockImplementation((url) => {
    if(url.indexOf('start') >= 0) {
      return { 
        data: { publicKey: { challenge: 'somechal' } },
        headers: { 
          get: (name) => {
            if (name === 'X-Simple-OTP-Web-Authn-Session-ID') {
              return 'sesh'
            }
            throw Error('unexpected header requested')
          }
        }
      }
    }
    return {
      data: { data: { id: 'someid', email: 'billg@microsoft.com', token: 'reallysecuretoken' } }
    }
  })

  window.PublicKeyCredential = {}
  navigator.credentials = { 
    create: () => {
      throw Error('should not call create here')
    },
    get: () => {
      return {
        id: 'somecred',
        rawId: new ArrayBuffer(1),
        response: {
          authenticatorData: new ArrayBuffer(2),
          clientDataJSON: new ArrayBuffer(3),
          signature: new ArrayBuffer(4),
          userHandle: new ArrayBuffer(5)
        },
        type: 'cooltype',
        authenticatorAttachment: 'reallyattached',
        getClientExtensionResults: () => { return {} }
      }
    }
  }

  const authResponse = await simpleOTP.authWithWebAuthnCredentials('billg@microsoft.com')
  expect(authResponse).toBeTruthy()
  expect(authResponse.data).toBeTruthy()
  expect(authResponse.data.email).toBe('billg@microsoft.com')
  expect(authResponse.data.token).toBe('reallysecuretoken')

  // Make sure the user saved to local storage has the same props as the user returned above
  expect(simpleOTP.getUser().email).toBe(authResponse.data.email)
  expect(simpleOTP.getUser().token).toBe(authResponse.data.token)
  expect(simpleOTP.isAuthenticated()).toBe(true)
})

test('auth() updates localStorage with the user details when the http call succeeds', async() => {
  const simpleOTP = new SimpleOTP('mocksiteid')
  const mockPost = vi.spyOn(http, 'post')
  mockPost.mockImplementation(() => {
    return { data: { data: { id: 'someid', email: 'billg@microsoft.com', token: 'reallysecuretoken' } } }
  })

  const authResponse = await simpleOTP.auth('reallysecurecode')
  expect(authResponse).toBeTruthy()
  expect(authResponse.data).toBeTruthy()
  expect(authResponse.data.email).toBe('billg@microsoft.com')
  expect(authResponse.data.token).toBe('reallysecuretoken')

  // Make sure the user saved to local storage has the same props as the user returned above
  expect(simpleOTP.getUser().email).toBe(authResponse.data.email)
  expect(simpleOTP.getUser().token).toBe(authResponse.data.token)
  expect(simpleOTP.isAuthenticated()).toBe(true)
})

test('auth() throws when the code is missing', async() => {
  const simpleOTP = new SimpleOTP('mocksiteid')
  const mockPost = vi.spyOn(http, 'post')
  simpleOTP.signOut()
  mockPost.mockImplementation(() => {
    return { data: { data: { id: 'someid', email: 'billg@microsoft.com', token: 'reallysecuretoken' } } }
  })

  expect(async () => await simpleOTP.auth()).rejects.toThrow()
  expect(simpleOTP.getUser()).toBeNull()
})

test('auth() returns the error code in the response when the http call returns an error response', async() => {
  const simpleOTP = new SimpleOTP('mocksiteid')
  const mockPost = vi.spyOn(http, 'post')
  mockPost.mockImplementation(() => {
    throw { 
      response: {
        data: {       
          code: 'invalid_auth_code', 
          message: 'bad auth code', 
          data: { id: 'someid', email: 'billg@microsoft.com', token: 'reallysecuretoken' } 
        } 
      }
    }
  })


  const res = await simpleOTP.auth('reallysecurecode')
  expect(res.code).toBe('invalid_auth_code')
  expect(res.message).toBe('bad auth code')

  expect(simpleOTP.getUser()).toBeNull()
  expect(simpleOTP.isAuthenticated()).toBe(false)
})

test('auth() returns a networking error in the response when the http call response does not have a response prop', async() => {
  const simpleOTP = new SimpleOTP('mocksiteid')
  const mockPost = vi.spyOn(http, 'post')
  mockPost.mockImplementation(() => {
    throw { 
      response2: {
        data: {       
          code: 'invalid_auth_code', 
          message: 'bad auth code', 
          data: { id: 'someid', email: 'billg@microsoft.com', token: 'reallysecuretoken' } 
        } 
      }
    }
  })

  const res = await simpleOTP.auth('reallysecurecode')
  expect(res.code).toBe(AuthStatusCode.NetworkingError.description)
  expect(res.message).toBe('Could not connect to the server. Try again in a few moments.')

  expect(simpleOTP.getUser()).toBeNull()
  expect(simpleOTP.isAuthenticated()).toBe(false)
})


test('authWithURLCode() updates localStorage with the user details when the http call succeeds', async() => {
  const simpleOTP = new SimpleOTP('mocksiteid')
  const mockPost = vi.spyOn(http, 'post')
  mockPost.mockImplementation(() => {
    return { data: { data: { id: 'someid', email: 'billg@microsoft.com', token: 'reallysecuretoken' } } }
  })

  window.location = { search: '?simpleotp_code=reallysecurecode'}

  const authResponse = await simpleOTP.authWithURLCode()
  expect(authResponse).toBeTruthy()
  expect(authResponse.data).toBeTruthy()
  expect(authResponse.data.email).toBe('billg@microsoft.com')
  expect(authResponse.data.token).toBe('reallysecuretoken')

  // Make sure the user saved to local storage has the same props as the user returned above
  expect(simpleOTP.getUser().email).toBe(authResponse.data.email)
  expect(simpleOTP.getUser().token).toBe(authResponse.data.token)
  expect(simpleOTP.isAuthenticated()).toBe(true)
})

test('authWithURLCode() throws when the code is missing from the url params', async() => {
  const simpleOTP = new SimpleOTP('mocksiteid')
  const mockPost = vi.spyOn(http, 'post')
  simpleOTP.signOut()
  mockPost.mockImplementation(() => {
    return { data: { data: { id: 'someid', email: 'billg@microsoft.com', token: 'reallysecuretoken' } } }
  })

  window.location = { search: '?not_a_simpleotp_code=reallysecurecode'}

  expect(async () => await simpleOTP.authWithURLCode()).rejects.toThrow()
  expect(simpleOTP.getUser()).toBeNull()
})

test('authWithURLCode() returns the error code in the response when the http call returns an error response', async() => {
  const simpleOTP = new SimpleOTP('mocksiteid')
  const mockPost = vi.spyOn(http, 'post')
  mockPost.mockImplementation(() => {
    throw { 
      response: {
        data: {       
          code: 'invalid_auth_code', 
          message: 'bad auth code', 
          data: { id: 'someid', email: 'billg@microsoft.com', token: 'reallysecuretoken' } 
        } 
      }
    }
  })

  window.location = { search: '?simpleotp_code=reallysecurecode'}

  const res = await simpleOTP.authWithURLCode()
  expect(res.code).toBe('invalid_auth_code')
  expect(res.message).toBe('bad auth code')

  expect(simpleOTP.getUser()).toBeNull()
  expect(simpleOTP.isAuthenticated()).toBe(false)
})

test('authWithURLCode() returns a networking error in the response when the http call response does not have a response prop', async() => {
  const simpleOTP = new SimpleOTP('mocksiteid')
  const mockPost = vi.spyOn(http, 'post')
  mockPost.mockImplementation(() => {
    throw { 
      response2: {
        data: {       
          code: 'invalid_auth_code', 
          message: 'bad auth code', 
          data: { id: 'someid', email: 'billg@microsoft.com', token: 'reallysecuretoken' } 
        } 
      }
    }
  })

  window.location = { search: '?simpleotp_code=reallysecurecode'}

  const res = await simpleOTP.authWithURLCode()
  expect(res.code).toBe(AuthStatusCode.NetworkingError.description)
  expect(res.message).toBe('Could not connect to the server. Try again in a few moments.')

  expect(simpleOTP.getUser()).toBeNull()
  expect(simpleOTP.isAuthenticated()).toBe(false)
})

test('isAuthenticated() returns false after the user is signed out', async() => {
  const simpleOTP = new SimpleOTP('mocksiteid')
  const mockPost = vi.spyOn(http, 'post')
  mockPost.mockImplementation(() => {
    return { data: { data: { email: 'billg@microsoft.com', token: 'reallysecuretoken' } } }
  })

  window.location = { search: '?simpleotp_code=reallysecurecode'}

  const user = await simpleOTP.authWithURLCode()
  expect(user).toBeTruthy()
  expect(simpleOTP.getUser()).toBeTruthy()
  expect(simpleOTP.isAuthenticated()).toBe(true)
  simpleOTP.signOut()
  expect(simpleOTP.isAuthenticated()).toBe(false)
  expect(simpleOTP.getUser()).toBe(null)
})