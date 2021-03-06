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
use yii\authclient\OAuth2;

/**
 * Weibo allows authentication via Weibo OAuth.
 * In order to use Weibo OAuth you must register your application at <http://open.weibo.com/>.
 * Example application configuration:
 * ~~~
 * 'components' => [
 *     'authClientCollection' => [
 *         'class' => 'yii\authclient\Collection',
 *         'clients' => [
 *             'facebook' => [
 *                 'class' => 'yii\authclient\clients\WeiBo',
 *                 'clientId' => 'facebook_client_id',
 *                 'clientSecret' => 'facebook_client_secret',
 *             ],
 *         ],
 *     ]
 *     ...
 * ]
 * ~~~
 *
 * @see http://open.weibo.com/
 * @see http://open.weibo.com/wiki/
 * @author Xu Tongle <xutongle@gmail.com>
 * @since 3.0
 */
class WeiBo extends OAuth2 {
    /**
     * @inheritdoc
     */
    public $authUrl = 'https://api.weibo.com/oauth2/authorize';
    /**
     * @inheritdoc
     */
    public $tokenUrl = 'https://api.weibo.com/oauth2/access_token';
    /**
     * @inheritdoc
     */
    public $apiBaseUrl = 'https://api.weibo.com';


    /**
     * @inheritdoc
     */
    public function init()
    {
        parent::init();
        if ($this->scope === null) {
            $this->scope = implode(',', [
                'follow_app_official_microblog',
            ]);
        }
    }

    /**
     * @inheritdoc
     */
    protected function defaultNormalizeUserAttributeMap() {
        return [ 'username'=> 'name' ];
    }

    /**
     * @inheritdoc
     */
    protected function initUserAttributes() {
        $openid = $this->api ( 'oauth2/get_token_info', 'POST' );
        return $this->api ( "2/users/show.json", 'GET', [ 'uid'=> $openid['uid'] ] );
    }

    /**
     * @inheritdoc
     */
    protected function defaultName() {
        return 'weibo';
    }

    /**
     * @inheritdoc
     */
    protected function defaultTitle() {
        return 'WeiBo';
    }

    /**
     * @inheritdoc
     */
    protected function defaultViewOptions() {
        return [ 'popupWidth'=> 800, 'popupHeight'=> 500 ];
    }
}