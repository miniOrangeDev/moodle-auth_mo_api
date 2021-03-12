Login using Moodle Users

Login using Moodle Users is an authentication plugin where users can login to their external applications and
Websites using their Moodle website credentials. Users will authenticate themselves via their Moodle credentials 
only once and they can access all the external applications. 
The plugin enables an API endpoint for the Moodle instance, which can be used for user authentication.
Any external application can query this API, and pass along the credentials for authentication. The plugin
validates the credentials against Moodle users, and returns the appropriate message in the API Response.

Steps to be followed:

1. Setup plugin in Moodle.

- Navigate to your Moodle admin dashboard to install and activate the Login using Moodle Users plugin.
- Open the Login using Moodle Users plugin settings and copy the User Authentication API URL and the User 
  Authentication Parameter.
- Enter the attributes name that you want to release to your application during the authentication.
- Click on the Save button to save your configurations.

2. Now configure your Authorization API and paste the User Authentication URL and User Authentication Parameters 
   that you copied in step 1 above. Test your Authorization API by providing your moodle credentials and you should
   be able to see a Success message.

Our miniOrange IDP service has pre-integrated support for Moodle API authentication, using which users can SSO into 
multiple applications without worrying about the SSO protocol. In this way, we achieve SSO for multiple external 
applications via their Moodle credentials.
