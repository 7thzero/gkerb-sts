# g-kerb-sts
Golang implementation of [kerb-sts](https://github.com/commercehub-oss/kerb-sts). This was written for 2 reasons:

1. To develop a better understanding of how Kerberos is used to authenticate with ADFS and Amazon AWS
2. Get past an issue I was having with kerb-sts where 'someting' in the environment changed and kerb-sts stopped working

# How to build
* Clone the repo
* go build

# Considerations
This is pretty raw with a lot of hard-coded entries, so be sure to follow the code and comments so you know what needs to be changed in your environment
