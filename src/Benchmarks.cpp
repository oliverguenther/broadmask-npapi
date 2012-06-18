//void BroadmaskAPI::run_benchmark_bes(int num_users, bool asImage, std::vector<int>& plaintext_sizes, int num_cycles, std::string path, BroadmaskAPI& api) {
//    
//    boost::filesystem::path folder (path);
//    
//    // Create parent directory if missing
//    if (!boost::filesystem::exists(folder))
//        boost::filesystem::create_directories(folder);
//    
//    // Out streams for data
//    ofstream os_setup_times (boost::filesystem::path(folder / "setup_time.data").string().c_str());
//    ofstream os_rsetup_times ((folder / "rsetup_time.data").string().c_str());    
//    ofstream os_enc_times ((folder / "enc_time.data").string().c_str());
//    ofstream os_dec_times ((folder / "dec_time.data").string().c_str());
//    
//    ofstream os_pubparam_size ((folder / "os_pubparam_size.data").string().c_str());
//    ofstream os_ciphertext_size ((folder / "os_ciphertext_size.data").string().c_str());
//    
//    // Setup times
//    boost::timer timer;
//    
//    // Test system for users = 2^1, 2^2, 2^n
//    for (int users = 2; users < num_users; users *= 2) {
//        
//        // setup phase
//        vector<std::string> s;
//        for (int c = 0; c < num_cycles; ++c) {
//            
//            // setup phase
//            timer.restart();
//            // create instance
//            std::string public_params = create_sender_instance("benchmark_bes", "benchmark_bes", users);
//            elapsed = timer.elapsed();
//            value_step(elapsed, setup);
//            
//            
//            // pub param size
//            value_step(public_params.size(), pubparam_size);
//            
//            
//            timer.restart();
//            for (int i = 1; i < users - 1; ++i) {
//                std::string user = boost::lexical_cast<std::string>(i);
//                add_member("benchmark_bes", user);
//                s.push_back(user);
//                
//                std::string privkey = get_member_sk("benchmark_bes", user);
//                create_receiver_instance(user, "bes_test_user", users, public_params, privkey);
//                if (c != num_cycles-1) {
//                    remove_instance(user);
//                }
//            }
//            elapsed = timer.elapsed();
//            value_step(elapsed, rsetup);
//            if (c != num_cycles-1) {
//                remove_instance("benchmark_bes");
//            }
//            
//        }
//        
//        
//        // encrypt to s, for each size
//        for (int p_i = 0; p_i < num_plaintexts; ++p_i) {
//            
//            // Create random plaintext array
//            int len = plaintext_sizes[p_i];
//            std::string message, ct_data, rec_message;
//            gen_random(message, len);
//            
//            for (int c = 0; c < num_cycles; ++c) {
//                
//                
//                // Encryption time
//                timer.restart();
//                FB::VariantMap enc_result = bes_encrypt_b64("benchmark_bes", s, message, false);
//                try {
//                    ct_data = enc_result["ciphertext"].convert_cast<std::string>();
//                    value_step(ct_data.size(), ciphertext_size[p_i]);
//                } catch (exception &e) {
//                    cerr << "Error on encryption op: " << e.what() << endl;
//                    return;
//                }
//                elapsed = timer.elapsed();
//                value_step(elapsed, enc[p_i]);
//                
//                for (int r = 0; r < s.size(); ++r) {
//                    timer.restart();
//                    FB::VariantMap dec_result = bes_decrypt_b64(s[r], ct_data, false);
//                    elapsed = timer.elapsed();
//                    value_step(elapsed, dec[p_i]);
//                    try {
//                        rec_message = dec_result["plaintext"].convert_cast<std::string>();
//                        if (message.compare(rec_message) != 0) {
//                            cout << "Decrypting using Receiver " << s[r] << " incorrect: " << endl;
//                            return;
//                        }
//                    } catch (exception& e) {
//                        cout << "Decrypting using Receiver " << s[r] << " incorrect: " << endl;
//                        return;
//                    }
//                }
//                
//            }
//        }
//        
//        
//        // print data
//        // Timing structure: <users> <average> <min> <max>
//        
//        
//        // setup
//        os_setup_times << users << " " << (setup[1] / num_cycles) << " " << setup[0] << " " << setup[2] << endl;
//        // receiver setup
//        os_rsetup_times << users << " " << (rsetup[1] / num_cycles) << " " << rsetup[0] << " " << rsetup[2] << endl;
//        
//        
//        // Enc / decryption times + ciphertext size
//        os_enc_times << users << " ";
//        os_dec_times << users << " ";
//        os_ciphertext_size << users << " ";
//        for (int p_i = 0; p_i < num_plaintexts; ++p_i) {
//            os_enc_times << enc[p_i][1] << " ";
//            os_dec_times << dec[p_i][1] << " ";
//            os_ciphertext_size << ciphertext_size[p_i][1] << " ";
//        }
//        os_enc_times << endl;
//        os_dec_times << endl;
//        os_ciphertext_size << endl;
//        
//        // Public params
//        os_pubparam_size << users << " " << pubparam_size[1] << endl;
//        
//        
//        // remove instances
//        istore->remove_instance("benchmark_bes");
//        for (int i = 0; i < num_cycles - 1; ++i) {
//            std::string user = boost::lexical_cast<std::string>(i);
//            istore->remove_instance(user);
//        }
//        
//    }
//    
//}
//
//bes_encryption_times run_bes_encryption(std::string& sender_instance, std::vector<std::string>& decrypt_instances, std::vector<std::string>& receivers, std::string& message, bool asImage, BroadmaskAPI& api) {
//    
//    bes_encryption_times times;
//    times.plaintext_size = message.size();
//        
//    boost::timer timer;
//    FB::VariantMap enc_result = bes_encrypt_b64(sender_instance, receivers, message, asImage);
//    times.enc_time = timer.elapsed();
//    
//    
//    std::string ct_data;
//    try {
//        ct_data = enc_result["ciphertext"].convert_cast<std::string>();
//        times.ciphertext_size = ct_data.size();
//    } catch (exception &e) {
//        cerr << "Error on encryption op: " << e.what() << endl;
//        return results;
//    }
//    
//    for (int r = 0; r < decrypt_instances.size(); ++r) {
//        timer.restart();
//        FB::VariantMap dec_result = bes_decrypt_b64(decrypt_instances[r], ct_data, asImage);
//        times.dec_times.push_back(timer.elapsed());
//        try {
//            std::string rec_message = dec_result["plaintext"].convert_cast<std::string>();
//            if (message.compare(rec_message) != 0) {
//                cout << "Decrypting using Receiver " << decrypt_instances[r] << " incorrect: " << endl;
//            }
//        } catch (exception& e) {
//            cout << "Decrypting using Receiver " << decrypt_instances[r] << " incorrect: " << endl;
//        }
//    }
//    
//    return times;
//    
//}
//
//void run_internal_testsuite(const FB::JSObjectPtr &callback) {
//    cout << "starting testcase" << endl;
//    create_sender_instance("foo",  "testsuite_instance", 256);
//    
//    BES_sender *sender = istore->load_instance<BES_sender>("foo");       
//    if (!sender) {
//        cout << "Sender instance foo should have been started, but wasn't" << endl;
//        return;
//    }
//    
//    int add1 = add_member("foo", "1");
//    int add2 = add_member("foo", "1");
//    
//    if (add1 != add2) {
//        cout << "Inserted IDs were " << add1 << " and " << add2 << " , which are not equal" << endl;
//        return;
//    }
//    
//    
//    remove_member("foo", "1");
//    int add3 = add_member("foo", "23");
//    if (add1 == add3)
//        cout << "New ID should not be old value " << add1 << endl;
//    
//    if (sender->member_id("23") != 1)
//        cout << "Member id should have been 1" << endl;
//    
//    if (sender->member_id("1") != -1)
//        cout << "Member '1' was not removed" << endl;
//    
//    istore->remove_instance("foo");
//    sender = istore->load_instance<BES_sender>("foo");
//    if (sender != NULL)
//        cout << "sender instance not deleted" << endl;
//    
//    boost::timer total;
//    std::string foo_pub_params = create_sender_instance("test", "test_instance", 256);
//    cout << "Setup phase: " << total.elapsed() << endl;
//    
//    vector<std::string> s;
//    for (int i = 0; i < 256; ++i) {
//        std::string user = boost::lexical_cast<std::string>(i);
//        add_member("test", user);
//        s.push_back(user);
//        
//        std::string privkey = get_member_sk("test", user);
//        create_receiver_instance(user, "test_user", 256, foo_pub_params, privkey);       
//    }
//    
//    
//    int size = 100000;
//    char *random = new char[size];
//    std::string rec_message_j;
//    std::string ct_data;
//    for (int i = 2; i <= 256; i*=2) {
//        vector<std::string> recipients;
//        for (int j = 0; j < i; ++j) {
//            recipients.push_back(s[j]);
//        }
//        cout << "System Test with " << i << "/256 recipients" << endl;
//        boost::timer round, step;
//        
//        gen_random(random, size-1);
//        std::string message(random);
//        step.restart();
//        FB::VariantMap enc_result = bes_encrypt_b64("test", recipients, message, false);
//        ct_data = enc_result["ciphertext"].convert_cast<std::string>();
//        
//        cout << "(ENC): " << i << " " << step.elapsed() << endl;
//        step.restart();
//        
//        cout << "(DEC): " << i << " ";
//        for (int j = 0; j < i; ++j) {
//            FB::VariantMap dec_result = bes_decrypt_b64(s[j], ct_data, false);
//            try {
//                rec_message_j = dec_result["plaintext"].convert_cast<std::string>();
//                if (message.compare(rec_message_j) != 0) {
//                    cout << "Decrypting using Receiver " << s[j] << " incorrect: " << endl;
//                    return;
//                }
//            } catch (exception& e) {
//                cout << "Decrypting using Receiver " << s[j] << " incorrect: " << endl;
//                return;
//            }
//            cout << step.elapsed() << " ";
//            step.restart();
//        }
//        
//        for (int j = i; j < 256; ++j) {
//            step.restart();
//            FB::VariantMap dec_result = bes_decrypt_b64(s[j], ct_data, false);
//            try {
//                std::string error = dec_result["error"].convert_cast<std::string>();
//                
//                if (dec_result.find("plaintext") != dec_result.end()) {
//                    cout << "Decrypting using Receiver " << s[j] << " yielded a result, but should not" << endl;
//                    return;
//                }
//            } catch (exception& e) {
//                cout << "Decrypting using Receiver " << s[j] << " should yield an error, but seems like there wasn't: " << e.what() << endl;
//                return;
//            }
//            cout << step.elapsed() << " ";
//        }
//        cout << endl;
//        
//        cout << "Round " << i << ": " << round.elapsed() << endl;
//        round.restart();
//    }
//    delete[] random;
//    
//    
//    cout << "Total time elapsed: " << total.elapsed() << endl;
//    
//    istore->remove_instance("test");
//    sender = istore->load_instance<BES_sender>("test");
//    if (sender != NULL)
//        cout << "sender instance not deleted" << endl;
//    
//    for (int i = 0; i < 256; ++i) {
//        std::string receiver = boost::lexical_cast<std::string>(i);
//        istore->remove_instance(receiver);
//        
//        if(istore->load_instance<BES_sender>(receiver))
//            cout << "Receiver instance " << receiver << " not deleted " << endl;
//        
//    }
//    
//    
//    callback->InvokeAsync("", FB::variant_list_of("it worked"));
//    
//}
