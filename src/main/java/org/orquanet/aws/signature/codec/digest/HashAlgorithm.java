/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.orquanet.aws.signature.codec.digest;

public enum HashAlgorithm {

    SHA256("SHA-256", 32, "HMACSHA256");

    private String algorithmName;
    private int hashLength;
    private String macAlgorithmName;

    HashAlgorithm(final String algorithmName, final int hashLength, final String macAlgorithmName) {
        this.algorithmName = algorithmName;
        this.hashLength = hashLength;
        this.macAlgorithmName = macAlgorithmName;
    }

    public String algorithmName() {
        return this.algorithmName;
    }

    public int hashLength() {
        return this.hashLength;
    }

    public String macAlgorithmName() {
        return this.macAlgorithmName;
    }
}
