<?php

  interface FluffModeratorInterface {
    /**
     * Constructor
     *
     * @access public
     * @author Chris Bestwick
     */
    public function __construct();

    /**
     * Sets up the plugin after initial installation.
     * 
     * Creates any necessary db tables and values and returns an array of tokens on success or errors on failure.
     *
     * @access public
     * @author Chris Bestwick
     * @return array
     */
    public function fluffSetup();

    /**
     * Creates a digest token.
     * 
     * Returns an array of digest token data on success or errors on failure.
     *
     * @access public
     * @author Chris Bestwick
     * @return array
     */
    public function fluffDigest();
        
    /**
     * Authenticates a request using digest token 
     * 
     * Returns an array containing a boolean true on success or errors on failure
     *
     * @access public
     * @author Chris Bestwick
     * @return array
     * 
     */
    public function fluffAuthenticate();

    /**
     * Gets unapproved comments
     * 
     * Returns an array containing comment data on success or errors on failure
     *
     * @access public
     * @author Chris Bestwick
     * @return array
     */
    public function fluffPoll();

    /**
     * Approves a comment
     * 
     * Returns an array containing a boolean true on success or errors on failure
     *
     * @access public
     * @author Chris Bestwick
     * @return array
     */
    public function fluffApprove();

    /**
     * Deletes a comment
     * 
     * Returns an array containing a boolean true on success or errors on failure
     *
     * @access public
     * @author Chris Bestwick
     * @return array
     */
    public function fluffDelete();

    /**
     * Edits a comment
     * 
     * Returns an array containing a boolean true on success or errors on failure
     *
     * @access public
     * @author Chris Bestwick
     * @return array
     */
    public function fluffEdit();
   
    /**
     * Returns the module version
     *
     * @access public
     * @author Chris Bestwick
     * @return array
     */
    public function fluffVersion();

     /**
     * Returns an error
     *
     * @access public
     * @author Chris Bestwick
     * @return array
     */
    public function fluffError($message);
    
    /**
     * Returns a json encoded string
     *
     * @access public
     * @author Chris Bestwick
     * @return string
     */
    public function fluffEncode($response);
    }
