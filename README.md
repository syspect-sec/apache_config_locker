#Explanation

Apache does not require its configuration file (httpd.conf) to be available once the service has been started, although it is needed for restarts.  
The configuration file is read into memory when the service starts and then it is not needed.  This is different than say, PHP config file (php.ini)
which is accessed for each page load.  

Apache's method of storing the configuration file in memory allows an opportunity to leverage it to load sensitive data into environment variables
when you start Apache and then encrypt the configuration file to store a copy of it.  This means you can avoid having plain-text passwords or other
credentials on the server.  

Once the environment variables are loaded into memory, PHP can access them directly and store them into a varaible instead of reading them from a file.

That is what Apache Configuration Locker script is used for.  Encrypting and decrypting the Apache Configuration file, so you can use it when you need it
and hide it when you don't.
