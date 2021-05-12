/* eslint-disable no-use-before-define */
const Axios = require('axios').default
const _ = require('lodash')
const CryptoJS = require('crypto-js')
const Crypto = require('crypto')
const NodeRSA = require('node-rsa')
const ShortId = require('shortid')

const REQ_METHOD = {
  POST: 'POST',
  GET: 'GET',
}

/**
   * @param {*} params = {
   *    "baseUrl": "https://haihau.com",
        "client": "client",
        "security": "true",
        "authorization": "asf.asfdasf.asf",
        "keys": {
          "privateKey": "",
          "publicKey": ""
        }
      }
  */
function RS(opts) {
  if (!(this instanceof RS)) return new RS(opts)

  const keys = _.get(opts, 'keys', null)
  const baseUrl = _.get(opts, 'baseUrl', null)
  const client = _.get(opts, 'client', null)
  const security = _.get(opts, 'security', false)

  if (!client) { throw new Error('RS object require "client"') }
  if (!baseUrl) { throw new Error('RS object require "base url"') }
  if (_.get(keys, 'privateKey', null) === null || _.get(keys, 'publicKey', null) === null) { throw new Error('RS object require keys { publicKey, privateKey }') }

  const rsaPub = new NodeRSA(keys.publicKey)
  const rsaPri = new NodeRSA(keys.privateKey)
  let authorization = _.get(opts, 'authorization') || ''

  this.SetAuth = function (auth) {
    authorization = auth || ''
  }

  this.Post = async function (path, body, headers) {
    const result = {
      code: -1,
      httpCode: null,
      data: null,
    }
    
    headers = _.isEmpty(headers) ? {} : headers
    _.set(headers, 'authorization', authorization)
    let endpoint = `${baseUrl}${path}`
    let data = body
    const configs = { headers, }
    if (security) {
      endpoint = baseUrl
      _.set(headers, '[\'x-api-client\']', client)
      const enc = PRIVATE.EncryptRequest({
        path,
        method: REQ_METHOD.POST,
        authorization,
        rsa: rsaPub,
        body,
        headers,
      })
      if (enc.code !== 1) {
        result.data = {
          message: _.get(enc, 'data.message', 'Invalid request'),
        }
        return result
      }
      data = enc.data
    }

    try {
      const response = await Axios.post(
        endpoint,
        data,
        configs
      )

      result.code = 1
      result.httpCode = response.status
      result.data = response.data

      if (security) {
        const dec = PRIVATE.DecryptResponse({
          path,
          client,
          method: REQ_METHOD.POST,
          authorization,
          rsa: rsaPri,
          body: response.data,
          headers: response.headers,
        })
        if (dec.code !== 1) {
          result.code = -3
          result.data = {
            message: _.get(dec, 'data.message', 'Invalid response'),
          }
          return result
        }
        
        result.data = dec.data
      }
      
      return result
    } catch (err) {
      result.code = -2
      result.httpCode = _.get(err, 'response.status', null)
      result.data = _.get(err, 'response.data', null)
      return result
    }
  }
}

const PRIVATE = {
  /**
   * @param {*} params = {
   *    "path": "/abcd",
        "client": "client",
        "method": "post",
        "authorization": "Aodfmd.sdgfsdg.sdgsd",
        "rsa": "NodeRSA",
        "body": {
          "x-api-message": ""
        },
        "headers": {
          "x-api-key": "",
          "x-api-client": "",
          "x-api-action": "",
          "x-api-validation", "",

        }
      }
  */
  DecryptResponse: (params) => {
    const result = {
      code: -1,
      data: null,
    }
    const headers = _.get(params, 'headers', null)
    const body = _.get(params, 'body', null)
    const path = _.get(params, 'path', null)
    const client = _.get(params, 'client', null)
    const method = _.get(params, 'method', null)
    const authorization = _.get(params, 'authorization') || ''
    const rsa = _.get(params, 'rsa', null)
    if (!headers || !method || !body || !rsa || !path || !client) {
      throw new Error('Invalid params')
    }

    const xAPIKey = headers['x-api-key']
    const xAPIClient = headers['x-api-client']
    const xAPIAction = headers['x-api-action']
    const xAPIValidation = headers['x-api-validation']
    const xAPIMessage = _.get(body, '[\'x-api-message\']', '')
    if (!xAPIKey || !xAPIClient || !xAPIAction || !xAPIValidation) {
      _.set(result, 'data.message', 'Invalid response')
      return result
    }

    if (client !== xAPIClient) {
      _.set(result, 'data.message', 'Invalid response')
      return result
    }
    
    let aesKey = null
    try {
      aesKey = rsa.decrypt(xAPIKey, 'utf8')
      if (!aesKey) {
        _.set(result, 'data.message', 'Invalid response')
        return result
      }
    } catch (err) {
      _.set(result, 'data.message', 'Invalid response')
      return result
    }

    const validation = `${xAPIAction}_${_.toUpper(method)}_${authorization}_${xAPIMessage}`
    const hmac = Crypto.createHmac('md5', aesKey).update(validation, 'utf8').digest('hex')
    if (hmac !== xAPIValidation) {
      _.set(result, 'data.message', 'Invalid response')
      return result
    }
    let apiPath = null
    try {
      apiPath = CryptoJS.AES.decrypt(xAPIAction, aesKey).toString(CryptoJS.enc.Utf8)
    } catch (err) {
      _.set(result, 'data.message', 'Invalid response')
      return result
    }
    if (apiPath !== path) {
      _.set(result, 'data.message', 'Invalid response')
      return result
    }

    let data = {}
    try {
      if (xAPIMessage !== '') {
        data = CryptoJS.AES.decrypt(xAPIMessage, aesKey).toString(CryptoJS.enc.Utf8)
        data = JSON.parse(data)
      }
    } catch (err) {
      _.set(result, 'data.message', 'Invalid response')
      return result  
    }

    result.code = 1
    result.data = data
    return result
  },

  /**
   * @param {*} params = {
   *    "path": "/abcd",
        "method": "post",
        "authorization": "Aodfmd.sdgfsdg.sdgsd",
        "rsa": "NodeRSA",
        "body": {
          
        },
        "headers": {
          "x-api-client": ""
        }
      }
  */
  EncryptRequest: (params) => {
    const result = {
      code: -1,
      data: null,
    }
    const headers = _.get(params, 'headers', null)
    const body = _.get(params, 'body', null)
    const path = _.get(params, 'path', null)
    const method = _.get(params, 'method', null)
    const authorization = _.get(params, 'authorization') || ''
    const rsa = _.get(params, 'rsa', null)
    if (!headers || !method || !body || !rsa || !path) {
      throw new Error('Invalid params')
    }

    const xAPIClient = headers['x-api-client']
    if (!xAPIClient) {
      _.set(result, 'data.message', 'Invalid request')
      return result
    }
    
    if (!xAPIClient) {
      _.set(result, 'data.message', 'Invalid request')
      return result
    }
    let xAPIKey = null
    let aesKey = null
    try {
      aesKey = ShortId.generate()
      xAPIKey = rsa.encrypt(aesKey, 'base64')
      if (!xAPIKey) {
        _.set(result, 'data.message', 'Invalid request')
        return result
      }
    } catch (err) {
      _.set(result, 'data.message', 'Invalid request')
      return result
    }

    const xAPIAction = CryptoJS.AES.encrypt(path, aesKey).toString()
    const xAPIMessage = CryptoJS.AES.encrypt(JSON.stringify(body), aesKey).toString()
    const validation = `${xAPIAction}_${_.toUpper(method)}_${authorization}_${xAPIMessage}`
    const hmac = Crypto.createHmac('md5', aesKey).update(validation, 'utf8').digest('hex')
    
    _.set(headers, 'x-api-key', xAPIKey)
    _.set(headers, 'x-api-action', xAPIAction)
    _.set(headers, 'x-api-validation', hmac)

    const data = {
      'x-api-message': xAPIMessage,
    }

    result.code = 1
    result.data = data
    return result
  },
}

module.exports = RS
