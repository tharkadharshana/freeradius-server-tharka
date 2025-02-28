#!/usr/bin/perl
#/etc/freeradius/3.0/custom/gpon.pm
# v.1.0.0 2025-01-15
use strict;
use DBI;
use Digest::MD5 qw(md5 md5_hex md5_base64);
use vars qw(%RAD_REQUEST %RAD_REPLY $dbh $conn_valid %conf);
use Config::Simple;
use File::Basename;
use warnings;

# RADIUS return values
use constant    RLM_MODULE_REJECT    => 0;
use constant    RLM_MODULE_OK        => 2;

# RADIUS log types
use constant    RAD_LOG_DEBUG        => 0;
use constant    RAD_LOG_ERROR        => 4;
use constant    RAD_LOG_INFO         => 3;

# Read the configuration file for MySQL connection details
sub read_conf {
#    Config::Simple->import_from('/etc/freeradius/3.0/config.conf', \%conf) or die Config::Simple->error();
	 Config::Simple->import_from('/etc/freeradius/3.0/config.conf', \ %conf) or die Config::Simple->error();

}

# Database connection function
sub conn_db {
    $dbh->disconnect() if defined $dbh;
    
    # Connect to MySQL database using values from config
    $dbh = DBI->connect("DBI:mysql:database=$conf{'mysql.db_name'};host=$conf{'mysql.db_host'}",
                        $conf{'mysql.db_user'},
                        $conf{'mysql.db_pass'}, 
                        { RaiseError => 1, AutoCommit => 1 });

    if ($DBI::err) {
        &radiusd::radlog(RAD_LOG_ERROR, "DB Connect Error. $DBI::errstr");
    } else {
        # Connection successful, no preparation of queries here
    }
    
    $conn_valid = (!$DBI::err);
}

# CLONE function to reinitialize configurations and DB connection
sub CLONE {
    &read_conf;
    &conn_db;
}

# Authorization function
sub authorize {
    my $usersID = $RAD_REQUEST{'User-Name'};  # Username from RADIUS request
    my $password = $RAD_REQUEST{'User-Password'};  # Password from RADIUS request
    my $sql = "SELECT value FROM radcheck WHERE username = ? AND attribute = 'Cleartext-Password'";

    &radiusd::radlog(RAD_LOG_INFO, "Handling authorization for $usersID");

    # Ensure database connection is valid
    if (!$conn_valid) {
        &conn_db;  # Repair connection if invalid
        if (!$conn_valid) {
            $RAD_REPLY{'Reply-Message'} = "Database connection error.";
            &radiusd::radlog(RAD_LOG_ERROR, "User $usersID rejected due to DB connect error.");
            return RLM_MODULE_REJECT;
        }
    }

    # Query the database for the user's password
    my $sth = $dbh->prepare($sql);
    $sth->execute($usersID);
    my ($stored_password) = $sth->fetchrow_array();
    $sth->finish;

    if (!$stored_password) {
        $RAD_REPLY{'Reply-Message'} = "User not found.";
        &radiusd::radlog(RAD_LOG_ERROR, "User $usersID not found.");
        return RLM_MODULE_REJECT;
    }

    # Compare the provided password with the stored password
    if ($stored_password ne $password) {
        $RAD_REPLY{'Reply-Message'} = "Invalid password.";
        &radiusd::radlog(RAD_LOG_ERROR, "User $usersID rejected due to invalid password.");
        return RLM_MODULE_REJECT;
    }

    # Successfully authenticated
    &radiusd::radlog(RAD_LOG_INFO, "User $usersID authorized successfully.");
    return RLM_MODULE_OK;
}

# Function to handle accounting (if needed)
sub accounting {
    my $usersID = $RAD_REQUEST{'User-Name'};
    my $sql = "INSERT INTO radacct (username, nasipaddress, acctstarttime) VALUES (?, ?, NOW())";

    &radiusd::radlog(RAD_LOG_INFO, "Handling accounting for $usersID");

    # Ensure database connection is valid
    if (!$conn_valid) {
        &conn_db;
        if (!$conn_valid) {
            &radiusd::radlog(RAD_LOG_ERROR, "User $usersID accounting failed due to DB connect error.");
            return RLM_MODULE_REJECT;
        }
    }

    # Insert accounting record into the database
    my $sth = $dbh->prepare($sql);
    $sth->execute($usersID, $RAD_REQUEST{'NAS-IP-Address'});
    $sth->finish;

    return RLM_MODULE_OK;
}

# Function to handle session termination (if needed)
sub postauth {
    my $usersID = $RAD_REQUEST{'User-Name'};
    my $sql = "UPDATE radacct SET acctstoptime = NOW() WHERE username = ? AND acctstoptime IS NULL";

    &radiusd::radlog(RAD_LOG_INFO, "Handling post-auth for $usersID");

    # Ensure database connection is valid
    if (!$conn_valid) {
        &conn_db;
        if (!$conn_valid) {
            &radiusd::radlog(RAD_LOG_ERROR, "User $usersID post-auth failed due to DB connect error.");
            return RLM_MODULE_REJECT;
        }
    }

    # Update session end time in the database
    my $sth = $dbh->prepare($sql);
    $sth->execute($usersID);
    $sth->finish;

    return RLM_MODULE_OK;
}

# Function to check for the health of the database connection
sub check_db_connection {
    if (!$conn_valid) {
        &conn_db;
        if (!$conn_valid) {
            &radiusd::radlog(RAD_LOG_ERROR, "Database connection could not be re-established.");
            return RLM_MODULE_REJECT;
        }
    }
    return 1; # Database connection is healthy
}
