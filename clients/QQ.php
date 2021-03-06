<?php
/**
 * @link http://www.yiiframework.com/
 * @copyright Copyright (c) 2008 Yii Software LLC
 * @license http://www.yiiframework.com/license/
 */

namespace yii\authclient\clients;

use Yii;
use yii\web\HttpException;
use yii\authclient\OAuth2;

/**
 * QQ allows authentication via QQ OAuth.
 * In order to use QQ OAuth you must register your application at <http://connect.qq.com/>.
 * Example application configuration:
 * ~~~
 * 'components' => [
 *     'authClientCollection' => [
 *         'class' => 'yii\authclient\Collection',
 *         'clients' => [
 *             'facebook' => [
 *                 'class' => 'yii\authclient\clients\QQ',
 *                 'clientId' => 'app_id',
 *                 'clientSecret' => 'app_secret',
 *             ],
 *         ],
 *     ]
 *     ...
 * ]
 * ~~~
 *
 * @see http://connect.qq.com/
 * @see http://wiki.connect.qq.com/
 * @author Xu Tongle <xutongle@gmail.com>
 * @since 3.0
 */
class QQ extends OAuth2
{
    /**
     * @inheritdoc
     */
    public $authUrl = 'https://graph.qq.com/oauth2.0/authorize';
    /**
     * @inheritdoc
     */
    public $tokenUrl = 'https://graph.qq.com/oauth2.0/token';
    /**
     * @inheritdoc
     */
    public $apiBaseUrl = 'https://graph.qq.com';

    /**
     * @inheritdoc
     */
    public function init()
    {
        parent::init();
        if ($this->scope === null) {
            $this->scope = implode(',', ['get_user_info']);
        }
    }

    /**
     * @inheritdoc
     */
    public function buildAuthUrl(array $params = [])
    {
        $state = $this->generateAuthState();
        $this->setState('state', $state);
        $params['state'] = $state;
        return parent::buildAuthUrl($params);
    }

    /**
     * @inheritdoc
     */
    public function fetchAccessToken($authCode, array $params = [])
    {
        $authState = $this->getState('state');
        if (!isset ($_REQUEST['state']) || empty ($authState) || strcmp($_REQUEST['state'], $authState) !== 0) {
            throw new HttpException (400, 'Invalid auth state parameter.');
        } else {
            $this->removeState('state');
        }
        return parent::fetchAccessToken($authCode, $params);
    }

    /**
     * @inheritdoc
     */
    protected function defaultNormalizeUserAttributeMap()
    {
        return ['username' => 'nickname'];
    }

    /**
     * @inheritdoc
     */
    protected function initUserAttributes()
    {
        $user = $this->api('oauth2.0/me', 'GET');
        if (isset ($user['error'])) {
            throw new HttpException (400, 'Invalid auth state parameter.');
        }
        $userAttributes = $this->api("user/get_user_info", 'GET', ['oauth_consumer_key' => $user['client_id'], 'openid' => $user['openid']]);
        $userAttributes['id'] = $user['openid'];
        return $userAttributes;
    }

    /**
     * @inheritdoc
     */
    protected function processResponse($rawResponse, $contentType = self::CONTENT_TYPE_AUTO)
    {
        if ($contentType === self::CONTENT_TYPE_AUTO && strpos($rawResponse, "callback") === 0) {
            $rawResponse = str_replace(['callback', '(', ')'], '', $rawResponse);
            $contentType = self::CONTENT_TYPE_JSON;
        }
        return parent::processResponse($rawResponse, $contentType);
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
    protected function defaultReturnUrl()
    {
        $params = $_GET;
        unset ($params['code']);
        unset ($params['state']);
        $params[0] = Leaps::$app->controller->getRoute();
        return Leaps::$app->getUrlManager()->createAbsoluteUrl($params);
    }

    /**
     * @inheritdoc
     */
    protected function defaultName()
    {
        return 'qq';
    }

    /**
     * @inheritdoc
     */
    protected function defaultTitle()
    {
        return 'QQ';
    }

    /**
     * @inheritdoc
     */
    protected function defaultViewOptions()
    {
        return ['popupWidth' => 800, 'popupHeight' => 500];
    }
}
