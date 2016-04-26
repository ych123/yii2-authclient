<?php
/**
 * Leaps Framework [ WE CAN DO IT JUST THINK IT ]
 *
 * @link http://www.tintsoft.com/
 * @copyright Copyright (c) 2012 TintSoft Technology Co. Ltd.
 * @license http://www.tintsoft.com/license/
 */

namespace yii\authclient\clients;

use yii;
use yii\web\HttpException;
use yii\authclient\OAuth2;

/**
 * Weixin(Wechat) allows authentication via Weixin(Wechat) OAuth.
 * In order to use Weixin(Wechat) OAuth you must register your application at <https://open.weixin.qq.com/>.
 * Example application configuration:
 * ~~~
 * 'components' => [
 *     'authClientCollection' => [
 *         'class' => 'yii\authclient\Collection',
 *         'clients' => [
 *             'wechat' => [
 *                 'class' => 'yii\authclient\clients\WeChat',
 *                 'clientId' => 'appid',
 *                 'clientSecret' => 'appkey',
 *             ],
 *         ],
 *     ]
 *     ...
 * ]
 * ~~~
 *
 * @see https://open.weixin.qq.com/
 * @see https://open.weixin.qq.com/cgi-bin/showdocument?action=dir_list&t=resource/res_list&verify=1&lang=zh_CN
 * @author Xu Tongle <xutongle@gmail.com>
 */
class WeChat extends OAuth2
{

    /**
     * @inheritdoc
     */
    public $authUrl = 'https://open.weixin.qq.com/connect/qrconnect';

    /**
     * @inheritdoc
     */
    public $tokenUrl = 'https://api.weixin.qq.com/sns/oauth2/access_token';

    /**
     * @inheritdoc
     */
    public $apiBaseUrl = 'https://api.weixin.qq.com';


    /**
     * @inheritdoc
     */
    public function init()
    {
        parent::init();
        if ($this->scope === null) {
            $this->scope = 'snsapi_login';
        }
    }

    /**
     * @inheritdoc
     */
    protected function defaultNormalizeUserAttributeMap()
    {
        return ['id' => 'openid', 'username' => 'nickname'];
    }

    /**
     * @inheritdoc
     */
    public function buildAuthUrl(array $params = [])
    {
        $state = $this->generateAuthState();
        $this->setState('state', $state);
        $defaultParams = [
            'appid' => $this->clientId,
            'response_type' => 'code',
            'redirect_uri' => $this->getReturnUrl(),
            'state' => $state,
        ];
        if (!empty($this->scope)) {
            $defaultParams['scope'] = $this->scope;
        }
        return $this->composeUrl($this->authUrl, array_merge($defaultParams, $params));
    }

    /**
     * @inheritdoc
     */
    public function fetchAccessToken($authCode, array $params = [])
    {
        $state = $this->getState('state');
        if (!isset ($_REQUEST['state']) || empty ($state) || strcmp($_REQUEST['state'], $state) !== 0) {
            throw new HttpException (400, 'Invalid auth state parameter.');
        } else {
            $this->removeState('state');
        }

        $defaultParams = [
            'appid' => $this->clientId,
            'secret' => $this->clientSecret,
            'code' => $authCode,
            'grant_type' => 'authorization_code'
        ];
        $response = $this->sendRequest('POST', $this->tokenUrl, array_merge($defaultParams, $params));
        $token = $this->createToken(['params' => $response]);
        $this->setAccessToken($token);

        return $token;
    }

    /**
     * @inheritdoc
     */
    protected function apiInternal($accessToken, $url, $method, array $params, array $headers)
    {
        $params['access_token'] = $accessToken->getToken();
        $params['openid'] = $accessToken->getParam('openid');
        return $this->sendRequest($method, $url, $params, $headers);
    }

    /**
     * @inheritdoc
     */
    protected function initUserAttributes()
    {
        return $this->api('sns/userinfo','GET');
    }

    /**
     * @inheritdoc
     */
    protected function defaultReturnUrl()
    {
        $params = $_GET;
        unset ($params['code']);
        unset ($params['state']);
        $params[0] = Leaps::$app->controller->getRoute();
        return Leaps::$app->getUrlManager()->createAbsoluteUrl($params);
    }

    /**
     * Generates the auth state value.
     *
     * @return string auth state value.
     */
    protected function generateAuthState()
    {
        return sha1(uniqid(get_class($this), true));
    }

    /**
     * @inheritdoc
     */
    protected function defaultName()
    {
        return 'wechat';
    }

    /**
     * @inheritdoc
     */
    protected function defaultTitle()
    {
        return 'WeChat';
    }

    /**
     * @inheritdoc
     */
    protected function defaultViewOptions()
    {
        return ['popupWidth' => 800, 'popupHeight' => 500];
    }
}