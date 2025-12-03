At the root of the repository:

```console
$ docker build -t deputy-demo -f internal/demo/Dockerfile .
```

Then use it:

```consoel
$ docker run --rm -it deputy-demo bash
```

```console
tester@baa0d63b833f:/app$ deputy proxy npm --policy policy/examples/shai-hulud-npm.yaml -- npm install react@v18.3.1
/time=2025-12-02T20:37:49.043Z level=INFO msg="request denied" package=react version=18.3.1 reason="package/version matches Wiz Shai-Hulud 2.0 IOC"
npm error code E403
npm error 403 403 Forbidden - GET http://127.0.0.1:45341/react/-/react-18.3.1.tgz
npm error 403 In most cases, you or one of your dependencies are requesting
npm error 403 a package version that is forbidden by your security policy, or
npm error 403 on a server you do not have access to.
npm error A complete log of this run can be found in: /home/tester/.npm/_logs/2025-12-02T20_37_47_914Z-debug-0.log
          
   ERROR  
          
  Exit status 1.                                                                                                      
```