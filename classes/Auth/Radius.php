<?php
/**
 * Class Auth_Radius
 * Radius driver for Kohana ORM
 */
class Auth_Radius extends Auth
{

    private $_radius = null;
    private $_username = null;

    /**
     * Constructor loads the user list into the class.
     */
    public function __construct($config = array())
    {
        parent::__construct($config);

        // Load user list
        //$this->_users = Arr::get($config, 'users', array());
    }

    /**
     * Logs a user in.
     *
     * @param   string   $username  Username
     * @param   string   $password  Password
     * @param   boolean  $remember  Enable autologin (not supported)
     * @return  boolean
     */
    protected function _login($username, $password, $remember)
    {

        $this->_username = $username;

        if ( $this->check_password( $password ) )
        {
            // Complete the login
            return $this->complete_login($username);
        }

        // Login failed
        return FALSE;
    }

    /**
     * Forces a user to be logged in, without specifying a password.
     *
     * @param   mixed    $username  Username
     * @return  boolean
     */
    public function force_login($username)
    {
        // Complete the login
        return $this->complete_login($username);
    }

    /**
     * Get the stored password for a username.
     *
     * @param   mixed   $username  Username
     * @return  string
     */
    public function password($username)
    {
        return false;
    }

    /**
     * Compare password with original (plain text). Works for current (logged in) user
     *
     * @param   string   $username  Username
     * @param   string   $password  Password
     *
     * @return  boolean
     */
    public function check_password($password)
    {

        $username = $this->_username;

        if ($username === FALSE)
        {
            return FALSE;
        }

        $this->init_radius();

		radius_put_attr( $this->_radius, RADIUS_USER_NAME,      $username );
		radius_put_attr( $this->_radius, RADIUS_USER_PASSWORD,  $password );

		// Todo: handle other responses: RADIUS_ACCESS_REJECT etc.
		return radius_send_request( $this->_radius ) === RADIUS_ACCESS_ACCEPT;

    }

    /**
     * Init radius
     * @return bool
     * @throws Exception
     */
    private function init_radius()
    {
        if($this->_radius !== null)
            return true;

        $this->_radius = radius_auth_open();

        if ( !radius_add_server( $this->_radius, $this->_config['host'], $this->_config['port'], $this->_config['secret'], $this->_config['timeout'], $this->_config['max_tries'] ) )
            $this->throw_error();

        if ( !radius_create_request( $this->_radius, RADIUS_ACCESS_REQUEST ) )
            $this->throw_error();

        return true;
    }

    /**
     * Throw error
     * @throws Exception
     */
    private function throw_error() {
        if($this->_radius !== null){
            throw new Exception( radius_strerror( $this->_radius ) );
        } else {
            throw new Exception( 'Authentication error before Radius initialization' );
        }
    }

}