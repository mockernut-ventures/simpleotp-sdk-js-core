import { expect, test, vi } from 'vitest'
import { AuthStatusCode, SignInStatusCode, SimpleOTP } from '../index'
import http from 'axios'

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


test('authWithURLCode() updates localStorage with the user details when the http call succeeds', async() => {
  const simpleOTP = new SimpleOTP('mocksiteid')
  const mockPost = vi.spyOn(http, 'post')
  mockPost.mockImplementation(() => {
    return { data: { data: { id: 'someid', email: 'billg@microsoft.com', token: 'reallysecuretoken' } } }
  })

  window.location = { search: '?simpleotp_code=reallysecurecode'}

  const authResponse = await simpleOTP.authWithURLCode('support@simpleotp.com')
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

  expect(async () => await simpleOTP.authWithURLCode('support@simpleotp.com')).rejects.toThrow()
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

  const res = await simpleOTP.authWithURLCode('support@simpleotp.com')
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

  const res = await simpleOTP.authWithURLCode('support@simpleotp.com')
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

  const user = await simpleOTP.authWithURLCode('support@simpleotp.com')
  expect(user).toBeTruthy()
  expect(simpleOTP.getUser()).toBeTruthy()
  expect(simpleOTP.isAuthenticated()).toBe(true)
  simpleOTP.signOut()
  expect(simpleOTP.isAuthenticated()).toBe(false)
  expect(simpleOTP.getUser()).toBe(null)
})