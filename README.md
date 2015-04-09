# freeradius-logwatch
Logwatch script for Freeradius written in Python

This python script will go through Freeradius's log file and output a nicely formatted list of successful authentication, failed authentications, as well as any info or error lines. The output list is sorted first by client_id, then by the username used to authenticate, and finally by the device MAC address used to log in. An example of the output is at the very end of this README.

To use this script put freeradius.py into /usr/share/logwatch/scripts/services and rename it to just freeradius.
Then create a file named freeradius.conf in /usr/share/logwatch/default.conf/logfiles and put the following inside:

> LogFile = radius/radius.log<br>
Archive = radius/radius.log-*.gz<br>
*ApplyStdDate<br>


Finally create a file named freeradius.conf in /usr/share/logwatch/default.conf/services and put the following inside:

> Title = "FreeRADIUS"<br>
LogFile = freeradius<br>
*RemoveHeaders<br>


After that you can manually run the logwatch command to see the Freeradius output is now included.

Here is a sample output showing successful and failed authentications:

> ---------------------&nbsp;FreeRADIUS&nbsp;Begin&nbsp;------------------------&nbsp;<br>
<br>
&nbsp;Successful&nbsp;Authentications&nbsp;(44):<br>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Client_1&nbsp;(19):<br>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;user1&nbsp;(5):<br>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;F0:B8:29:43:FC:39&nbsp;-&nbsp;1&nbsp;Time(s)<br>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;A0:00:FF:BA:0A:64&nbsp;-&nbsp;4&nbsp;Time(s)<br>
&nbsp;<br>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;user2&nbsp;(14):<br>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;00:FF:D2:F5:A7:BB&nbsp;-&nbsp;6&nbsp;Time(s)<br>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;E0:BB:7D:34:1B:49&nbsp;-&nbsp;8&nbsp;Time(s)<br>
&nbsp;<br>
&nbsp;<br>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Client_2&nbsp;(25):<br>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;user2&nbsp;(19):<br>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;00:FF:D2:F5:A7:BB&nbsp;-&nbsp;2&nbsp;Time(s)<br>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;E0:BB:7D:34:1B:49&nbsp;-&nbsp;17&nbsp;Time(s)<br>
&nbsp;<br>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;user3&nbsp;(6):<br>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;F8:F1:B6:F5:99:D1&nbsp;-&nbsp;6&nbsp;Time(s)<br>
&nbsp;<br>
&nbsp;<br>
&nbsp;Failed&nbsp;Authentications&nbsp;(2)<br>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Client_1&nbsp;(2):<br>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;test&nbsp;(1):<br>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;00:15:C9:FF:2A:3B&nbsp;-&nbsp;1&nbsp;Time(s)<br>
&nbsp;<br>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;anontest&nbsp;(1):<br>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;00:15:C9:FF:2A:3B&nbsp;-&nbsp;1&nbsp;Time(s)<br>
&nbsp;<br>
----------------------&nbsp;FreeRADIUS&nbsp;End&nbsp;-------------------------
