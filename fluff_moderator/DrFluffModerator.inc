<?php

  require_once 'encode.php';

  class DrFluffModerator implements FluffModeratorInterface {
    /**
     * An array to hold all response data from requests including any errors
     *
     * @access protected
     * @var array
     * 
     * possible array indices
     * $response['unauthorised'] - set to true if the user is not authenticated during setup
     * $response['cannot_moderate'] - set to true during setup if user does not have moderation rights
     * $response['duplicate'] - set to true if the setup has previously run ok
     * $response['error'] - set by fluff_error() in the event of db problems, a string containing a meaningful error message
     * $response['fluff'] - the fluff token returned during a succesful setup, as a string
     * $response['user'] - the fluff user token returned during a successful setup, as a string
     * $response['digest_data'] - an array containing the fluff digest token, $response['digest_data']['token'] 
     * and timestamp, $response['digest_data']['time'] returned by the fluff_digest method, as a string
     * $response['unapproved_request'] - set to true if the digest token request process is not authenticated
     * $response['data'] - contains the unapproved comment data, as an array
     * $response['number'] - the number of unapproved comments
     * $response['success'] -  set to true if the approve, delete or edit methods execute sucessfully
     * $response['version'] - contains the version number 
     * 
     * the $response array is returned to the mod.fluff_moderator calling methods and there 
     * encoded using the fluff_encode method before being printed to the browser, - currently encoded as a json string
     */ 
    protected $response;
    
    /**
     * The version number of the module
     *
     * @access protected
     * @var integer
     */
    protected $version_number;
    
    /**
     * The type of action to perfom, e.g. poll, delete, etc
     *
     * @access public
     * @var string
     */
    public $operation;
    
    /**
     * contains the comment id during approve, delete and edit method calls, and the fluff_user_token during the digest method call
     *
     * @access protected
     * @var string
     */
    protected $id;
        
    /**
     * The edited comment content
     *
     * @access protected
     * @var string
     */
    protected $comment_content;
    
    /**
     * Various tokens to authenticate the request
     *
     * @access protected
     * @var string
     */
    protected $auth_field;
      
    /**
     * Constructor
     *
     * @access public
     * @author Chris Bestwick
     */
    public function __construct() {
//  sanitize post input data and set variables
    if ( isset($_POST['action'] ) == true ) {
      $this->operation = $_POST['action']; 
    }   
    if ( isset($_POST['id'] ) == true ) {
      $this->id = $_POST['id'];
    }
    if ( isset($_POST['comment'] ) == true ) {
      $this->comment_content = $_POST['comment']; 
    }
    if ( isset($_POST['auth-field'] ) == true ) {
      $this->auth_field = $_POST['auth-field']; 
    }
      $this->response = array();
      $this->version_number = 1.0;
    }
    
    /* (non-PHPdoc)
     * @see FluffModeratorInterface::fluffSetup()
     */
    public function fluffSetup() {
        
//    authenticate username and password
      $authentic_user = user_authenticate($_POST['dog'], $_POST['fish']);
      
//    if they're not authentic      
      if ($authentic_user == false) {
        $this->response['unauthorised'] = true;
      }
      else {          
          
//      get the user id for that username 
        $user_id = $authentic_user;
        
//      check whether the user has the right to moderate comments 

//      first get the role id (rid)        
        try {
          $result = db_select('users_roles', 'u')
          ->fields('u', array('rid'))
          ->condition('u.uid', $user_id,'=')
          ->execute()
          ->fetchAssoc();
          $user_role = $result['rid'];
        }
        catch (PDOException $e) {
          $this->fluffError('db setup error');
          return $this->response;
        } 
        
//      if there is an rid (authenticated users appear not to have one (?)) see if that role can moderate comments        
        if ( false == isset($user_role) ) {
//        if no rid, definitely no moderation rights
          $this->response['cannot_moderate'] = true; 
          return $this->response; 
        }
        else {
          try {
            $result = db_select('role_permission', 'r')
            ->fields('r', array('module'))
            ->condition('r.rid', $user_role,'=')
            ->condition('r.permission', 'administer comments', '=')
            ->execute()
            ->fetchAssoc();
          }
          catch (PDOException $e) {
            $this->fluffError('db setup error');
            return $this->response;
          }    
//          if $result is false it means there's no administer comments permission for this role id
            if ( false == $result) {
              $this->response['cannot_moderate'] = true; 
              return $this->response;    
            }         
          
        }

//      check whether the plugin has already been set up by trying to get the fluff token
        try {
          $result = db_select('fluff_tokens', 'f')
          ->fields('f', array('token'))
          ->condition('f.member_id', $user_id,'=')
          ->execute()
          ->fetchAssoc();
          $fluff_token = $result['token'];
        }
        catch (PDOException $e) {
          $this->fluffError('db setup error');
          return $this->response;
        }  

//      if there is a token, set a message and return
        if ( false == empty($fluff_token) ) {
          $this->response['duplicate'] = true; 
          return $this->response; 
        }  

//      generate fluff token and fluff user token and store them in the db
        $fluff_token = $this->random_string(128);
        $fluff_user_token = $this->random_string(128);
        
        try {
          $insert = db_insert('fluff_tokens')
          ->fields(array('member_id' => $user_id, 'token' => $fluff_token, 'user_token' => $fluff_user_token))
          ->execute();
          
          $this->response['fluff'] = $fluff_token;
          $this->response['user'] = $fluff_user_token;
        }
        catch (PDOException $e) {
          $this->fluffError('db setup error');
          return $this->response;
        }                            
      }
      
      return $this->response;
    }
        
    /* (non-PHPdoc)
     * @see FluffModeratorInterface::fluffDigest()
     */
    public function fluffDigest() {
//    generate the digest code using custom function below 
      $digest = $this->random_string(128);    

//    store it in an array, with a timestamp, then serialize
      $digest_created = time(); 
      $digest_data = array();
      $digest_data['token'] = $digest;
      $digest_data['time'] = $digest_created;
      $serialised_digest_data = serialize( $digest_data );
      
//    delete any existing digest tokens which may have been left by a previously failed authentication attempt
      try {  
        db_update('fluff_tokens')  
        ->fields(array('digest_token' => NULL)) 
        ->condition('user_token', $this->id)
        ->execute(); 
      }   
      catch (PDOException $e) {
        $this->fluffError('1 db digest delete error');
        return $this->response;
      }
                
//    save the serialized digest data to the db  
      try {                                
        db_update('fluff_tokens')  
        ->fields(array('digest_token' => $serialised_digest_data)) 
        ->condition('user_token', $this->id)
        ->execute();
      
        $this->response['digest_data'] = $digest_data;  
      }
      catch (PDOException $e) {
        $this->fluffError('db digest insert error');
        return $this->response;
      }
      
      return $this->response;
    }
        
    /* (non-PHPdoc)
     * @see FluffModeratorInterface::fluffAuthenticate()
     * based on ircmaxell's post in http://stackoverflow.com/questions/5373016/php-passing-data-from-a-site-to-another-site-securely
     */
    public function fluffAuthenticate() {
//    parse the auth-field query variable into user token, hash and digest token        
      list ( $user, $hash, $token ) = explode( ':', $this->auth_field );
                      
//    get the fluff token and digest token from the db based on the fluff user token stored in $user
      try {
        $result = db_select('fluff_tokens', 'f')
        ->fields('f', array('token', 'digest_token'))
        ->condition('f.user_token', $user,'=')
        ->execute()
        ->fetchAssoc();
        $fluff_token = $result['token']; 
        $digest_data = $result['digest_token'];             
        $unserialized_digest_data = unserialize( $digest_data );
      }
      catch (PDOException $e) {
        $this->fluffError('db authenticate request error');
      } 
                
//    delete the digest code from the db whether fluffAuthenticate() succeeds or fails; it's one-time use only 
//    (if this fails, any new digest request takes care of any orphaned digest tokens)
      try {  
        db_update('fluff_tokens')  
        ->fields(array('digest_token' => NULL)) 
        ->condition('user_token', $user)
        ->execute(); 
      }   
      catch (PDOException $e) {
        $this->fluffError('db digest delete error');
      }
        
//    compare the digest token with the one sent in the cURL request, and check it's not too old 
      $token_life_secs = 20;
        
      if ( ( $unserialized_digest_data['token'] == $token ) && ( time() - $unserialized_digest_data['time'] > $token_life_secs == false ) ) {
//      if all's ok, do this final check
        $stub = $user . ':' . $fluff_token;
        if ( $hash == hash_hmac( 'sha256', $stub, $token ) ) {
//        authenticated user
          return true;
        } 
        else {
          $this->response['unapproved_request'] = true;
        }  
      } 

      return $this->response;
    }
        
    /* (non-PHPdoc)
     * @see FluffModeratorInterface::fluffPoll()
     */
    public function fluffPoll() {       
//    retrieve unpublished comments.
      try {
        $result = db_query('SELECT c.cid, c.subject, c.created, c.name, n.title, f.comment_body_value
          FROM {comment} c 
          INNER JOIN {node} n ON c.nid = n.nid AND c.status = :status 
          INNER JOIN {field_data_comment_body} f ON c.cid = f.entity_id', array(':status' => 0));
      }
      catch (PDOException $e) {
        $this->fluffError('db poll error');
        return $this->response;
      }
      
//    an initialised value for the number of comments        
      $number = 0;
      
//    standardise the array keys for the comment data 
      $standard_row = array();       
      foreach($result as $row) {
        $standard_row['id'] = $row->cid;
        $standard_row['author'] = \Encoding\encodeString($row->name);
        $standard_row['date'] = date('Y-m-d H:i:s', $row->created);
        $standard_row['content'] = \Encoding\encodeString($row->comment_body_value);
        $standard_row['post_title'] = \Encoding\encodeString($row->title); 
//      drupal has a comment title as well as comment body for each comment. 
        $standard_row['comment_title'] = \Encoding\encodeString($row->subject);           
            
        $this->response['data'][] = $standard_row;
        $number++;
      }
        $this->response['number'] = $number;
        
        return $this->response;
    }
        
    /* (non-PHPdoc)
     * @see FluffModeratorInterface::fluffApprove()
     */
    public function fluffApprove() {
//    update the status column to published  
      try {
        $result = db_update('comment')  
        ->fields(array('status' => 1)) 
        ->condition('cid', $this->id)
        ->execute();  

//      set an error in the case of a duplicated request
        if ( $result === 1 ) {        
        $this->response['success'] = true; 
        }
        else {
          $this->fluffError('db approve error');
        }
      }
      catch (PDOException $e) {
        $this->fluffError('db approve error');
      }  

      return $this->response;
    }
        
    /* (non-PHPdoc)
     * @see FluffModeratorInterface::fluffDelete()
     */
    public function fluffDelete() {
//    delete the comment
      try { 
      $result = db_query("DELETE c, f FROM {comment} c 
        INNER JOIN {field_data_comment_body} f ON c.cid = f.entity_id AND c.cid = :id", array(':id' => $this->id));

//      set an error in the case of a duplicated request (use rowCount here as the db_query result is an object)
        if ( $result->rowCount() !== 0 ) {        
        $this->response['success'] = true; 
        }
        else {
          $this->fluffError('db delete error');
        } 
      }
      catch (PDOException $e) {
        $this->fluffError('db delete error');
      } 

      return $this->response;
    }
        
    /* (non-PHPdoc)
     * @see FluffModeratorInterface::fluffEdit()
     */
    public function fluffEdit() {
//    update the comment content 
      try {
        $comment_result = db_update('field_data_comment_body')  
        ->fields(array('comment_body_value' => $this->comment_content)) 
        ->condition('entity_id', $this->id)
        ->execute(); 
      }
      catch (PDOException $e) {
        $this->fluffError('db edit error');
        return $this->response;
      }  
                
//    update the status column to published
      try {
        $status_result = db_update('comment')  
        ->fields(array('status' => 1)) 
        ->condition('cid', $this->id)
        ->execute();                  
                
//      set an error in the case of a duplicated request
        if ( $comment_result === 1 && $status_result === 1) {        
        $this->response['success'] = true; 
        }
        else {
          $this->fluffError('db edit error');
        }
      }
      catch (PDOException $e) {
        $this->fluffError('db edit error');
      } 
      
      return $this->response;
    }
        
    /* (non-PHPdoc)
     * @see FluffModeratorInterface::fluffVersion()
     */
    public function fluffVersion() {
      $this->response['version'] = $this->version_number;
      return $this->response;
    }
    
    /* (non-PHPdoc)
     * @see FluffModeratorInterface::fluffError()
     */
    public function fluffError($message) {
      $this->response['error'] = $message;
      return $this->response;        
    }
    
    /* (non-PHPdoc)
     * @see FluffModeratorInterface::fluffEncode()
     */
    public function fluffEncode($response) {
      return json_encode($response);
    }
    
    /**
     * Generate random string
     *
     * @access private
     * @author Rathienth Baskaran, http://stackoverflow.com/questions/1846202/php-how-to-generate-a-random-unique-alphanumeric-string
     * @param integer $length
     * @return string
     */ 
    private function random_string( $length ) {
      $key = '';
      $keys = array_merge( range(0, 9), range('a', 'z') );
    
      for ( $i = 0; $i < $length; $i++ ) {
        $key .= $keys[array_rand($keys)];
      }
    
      return $key;
    }
  }
  
  
