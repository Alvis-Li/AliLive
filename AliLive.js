const moment = require('moment');
const urllib = require('urllib');
const utility = require('utility');
const crypto = require('crypto');

const config = {
  Format: 'JSON',
  Method: 'POST',
  AppName: '',
  GateWay: 'https://live.aliyuncs.com/',
  Version: '2016-11-01',
  DataType: 'json',
  DomainName: '',
  AccessKeyId: '',
  SignatureMethod: 'HMAC-SHA1',
  AccessKeySecret: '',
  SignatureVersion: '1.0',
  PrivateKey: ''
};

/**
 * requestData = {
 *  accessKeyId:"",
 *  accessKeySecret:"",
 *  Action:'DescribeLiveStreamOnlineUserNum',
 *  DomainName:'app.rtmp.domian.com',
 *  AppName:'appname',
 *  StreamName:'streamName',
 * }
 *
 */
module.exports = {
  requestCDNResource: function(requestData, callback) {
    requestData['DomainName'] = requestData['DomainName'] || config.DomainName;
    requestData['AppName'] = requestData['AppName'] || config.DomainName;

    const ApiPublicParam = {
      Format: config.Format,
      Version: config.Version,
      AccessKeyId: config.AccessKeyId,
      SignatureMethod: config.SignatureMethod,
      Timestamp: moment().utc().format(),
      SignatureVersion: config.SignatureVersion,
      SignatureNonce: (new Date()).getTime() + "" + Math.round(Math.random() * 100),
    };

    const param = requestData;
    let query = Object.assign({}, ApiPublicParam, param);
    let sortQuery = {}
    let pureSortQuery = []
    for (let key of Object.keys(query).sort()) {
      let valueStr = query[key] + '';
      valueStr = valueStr.replace(/:/g, '%3A');
      valueStr = valueStr.replace(/\//g, '%2F');
      valueStr = valueStr.replace(/{/g, '%7B');
      valueStr = valueStr.replace(/}/g, '%7D');
      valueStr = valueStr.replace(/,/g, '%2C');
      let value = utility.encodeURIComponent(valueStr);
      key = utility.encodeURIComponent(key);
      sortQuery[key] = value
      pureSortQuery.push(key + "=" + value);
    }

    let queryStr = pureSortQuery.join("&");
    let stringToSign = config.Method + '&%2F&' + queryStr.replace(/=/g, "%3D").replace(/&/g, "%26");
    let signature = crypto.createHmac('sha1', config.AccessKeySecret + '&');
    let signatureStr = signature.update(new Buffer(stringToSign, 'utf8')).digest('base64');
    let aliUrl = config.GateWay;
    let fullParam = Object.assign(query, {
      Signature: utility.encodeURIComponent(signatureStr),
      Timestamp: query.Timestamp
    })
    let paramList = [];
    for (let key of Object.keys(fullParam)) {
      let value = fullParam[key] + "";
      if (value.match(/:/g)) {
        value = value.replace(/:/g, '%3A');
      } else if (value.match(/\//g) || value.match(/{/g) || value.match(/,/g)) {
        value = utility.encodeURIComponent(value);
      }
      paramList.push(key + "=" + value);
    }
    let paramStr = paramList.join('&');
    let realUrl = aliUrl + '?' + paramStr;

    urllib.request(realUrl, {
      method: config.Method,
      dataType: config.DataType,
    }, callback);
  },
  authKey: function(URI) { //URL鉴权计算逻辑
    URI = url.parse(URI).pathname;
    let Timestamp = moment().add(600, 's').unix();
    let rand = 0;
    let uid = 0;
    let PrivateKey = config.PrivateKey; //(即开通鉴权功能时填写的鉴权KEY)
    let sstring = URI + '-' + Timestamp + '-' + rand + '-' + uid + '-' + PrivateKey;
    let HashValue = md5(sstring)
    return {
      auto_key: HashValue
    };
  }
};
