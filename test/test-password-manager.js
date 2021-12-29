"use strict";

var expect = require('expect.js');
var passwordManager = require('../password-manager');

describe('Password manager', function() {
    this.timeout(5000);
    var password = "password123!";
    var keychain;

    var kvs = {
        "service1": "value1",
        "service2": "value2",
        "service3": "value3"
    };

    beforeEach(function() {
        keychain = passwordManager.keychain();
    });

    describe('functionality', function() {

        it('inits without an error', function() {
            keychain.init(password);
        });

        it('can set and retrieve a password', function() {
            keychain.init(password);
            var url = 'www.stanford.edu';
            var pw = 'sunetpassword';
            keychain.set(url, pw);
            expect(keychain.get(url)).to.equal(pw);
        });

        it('can set and retrieve multiple passwords', function() {
            keychain.init(password);
            for (var k in kvs) {
                keychain.set(k, kvs[k]);
            }
            for (var k in kvs) {
                expect(keychain.get(k)).to.equal(kvs[k]);
            }
        });

        it('throws an error if trying to set when the keychain is not ready', function() {
            expect(function() {
                keychain.set('a', 'b');
            }).to.throwException();
        });

        it('returns null for non-existent passwords', function() {
            keychain.init(password);
            for (var k in kvs) {
                keychain.set(k, kvs[k]);
            }
            expect(keychain.get('www.stanford.edu')).to.be(null);
        });

        it('can remove a password', function() {
            keychain.init(password);
            for (var k in kvs) {
                keychain.set(k, kvs[k]);
            }
            expect(keychain.remove('service1')).to.be(true);
            expect(keychain.get('service1')).to.be(null);
        });

        it('returns false if there is no password for the domain being removed', function() {
            keychain.init(password);
            for (var k in kvs) {
                keychain.set(k, kvs[k]);
            }
            expect(keychain.remove('www.stanford.edu')).to.be(false);
        });

        it('can dump and restore the database', function() {
            keychain.init(password);
            for (var k in kvs) {
                keychain.set(k, kvs[k]);
            }
            var data = keychain.dump();
            var contents = data[0];
            var checksum = data[1];
            var newKeychain = passwordManager.keychain();

            // Make sure it's valid JSON
            expect(function() {
                JSON.parse(contents)
            }).not.to.throwException();
            expect(newKeychain.load(password, contents, checksum)).to.be(true);
            for (var k in kvs) {
                expect(keychain.get(k)).to.equal(kvs[k]);
            }
        });

        it('fails to restore the database if checksum is wrong', function() {
            keychain.init(password);
            for (var k in kvs) {
                keychain.set(k, kvs[k]);
            }
            var data = keychain.dump();
            var contents = data[0];
            var fakeChecksum = '3GB6WSm+j+jl8pm4Vo9b9CkO2tZJzChu34VeitrwxXM=';
            var newKeychain = passwordManager.keychain();
            expect( function() {
                newKeychain.load(password, contents, fakeChecksum);
            }).to.throwException();
        });

        it('returns false if trying to load with an incorrect password', function() {
            keychain.init(password);
            for (var k in kvs) {
                keychain.set(k, kvs[k]);
            }
            var data = keychain.dump();
            var contents = data[0];
            var checksum = data[1];
            var newKeychain = passwordManager.keychain();
            expect(newKeychain.load("fakepassword", contents, checksum)).to.be(false);
        });
    });

    describe('security', function() {

        // Very basic test to make sure you're not doing the most naive thing
        it("doesn't store domain names and passwords in the clear", function() {
            keychain.init(password);
            var url = 'www.stanford.edu';
            var pw = 'sunetpassword';
            keychain.set(url, pw);
            var data = keychain.dump();
            var contents = data[0];
            expect(contents).not.to.contain(password);
            expect(contents).not.to.contain(url);
            expect(contents).not.to.contain(pw);
        });

        // This test won't be graded directly -- it just exists to make sure your
        // dump include a kvs object with all your urls and passwords, because
        // we will be using that in other tests.
        it('includes a kvs object in the serialized dump', function() {
            keychain.init(password);
            for (var i = 0; i < 10; i++) {
                keychain.set(String(i), String(i));
            }
            var data = keychain.dump();
            var contents = data[0];
            var contentsObj = JSON.parse(contents);
            expect(contentsObj).to.have.key('kvs');
            expect(contentsObj.kvs).to.be.an('object');
            expect(Object.getOwnPropertyNames(contentsObj.kvs)).to.have.length(10);
        })

    });
});