# These MUST be defined before the includes.
LANGUAGE = java
GEN_DIR  = ./generated

# A Java class is generated for each sum type variant.
# Each variant contains a `public enum TagEnum { <constructor>; ... }"`
# where <constructor> is something like DVInt or DVTest.
# Different versions of openapi-generate-cli name than differently, e.g., DVInt viz DV_Int.
# These renames are to maintain consistency of naming regardless of openapi-generate-cli version.
#
# TODO: UNSUPPORTEDFEATURE and REVEALPRIVACYWARNING renames are not working.
# The consequence of this not working is that manually written Java code needs to refer to the nonsnakecase name.
# See src/main/java/com/example/vcp/demos/Util.java for examples of using sum types.
#
# If the following (optional) variable is set, it MUST be set before the includes.
GENERATE_CONFIG = \
  --enum-name-mappings DVInt=DV_INT,DVText=DV_TEXT \
  --enum-name-mappings SPVOne=SPV_ONE,SPVList=SPV_LIST \
  --enum-name-mappings UNSUPPORTEDFEATURE=UNSUPPORTED_FEATURE \
  --enum-name-mappings REVEALPRIVACYWARNING=REVEAL_PRIVACY_WARNING

include ../Makefile-openapi

# Sum types (e.g., DataValue) get generated as a base class (e.g., DataValue.java)
# and a class for each variants.  But the class names are, e.g., DataValueOneOf, DataValueOneOf1, ...
# So, for ease of use, the class and all references to them are renamed (e.g., DVInt, DVText).
# This is done via the rename Makefile canned recipe, that renames generated files via `mv`
# and renames references to them in all files via `sed`.

MAIN_CODE_DIR=$(CODE_GEN_DIR)/src/main/java
TEST_CODE_DIR=$(CODE_GEN_DIR)/src/test/java

define rename
	mv   $(MAIN_CODE_DIR)/$(COM_slash_EXAMPLE_slash_VCP)/$(MODEL_PACKAGE_WITH_SLASH)/$1.java \
             $(MAIN_CODE_DIR)/$(COM_slash_EXAMPLE_slash_VCP)/$(MODEL_PACKAGE_WITH_SLASH)/$2.java
	mv   $(TEST_CODE_DIR)/$(COM_slash_EXAMPLE_slash_VCP)/$(MODEL_PACKAGE_WITH_SLASH)/$1Test.java \
             $(TEST_CODE_DIR)/$(COM_slash_EXAMPLE_slash_VCP)/$(MODEL_PACKAGE_WITH_SLASH)/$2Test.java
	find $(CODE_GEN_DIR) -name "*.java" -type f \
             | xargs sed -i 's/$1/$2/g'
endef

.PHONY: tweak-generated-code
tweak-generated-code:
	find $(CODE_GEN_DIR) -name "*.java" -type f \
             | xargs sed -i -e '/javax.annotation.Generated/d'
	find $(CODE_GEN_DIR) -name "*.java" -type f \
             | xargs sed -i -e '/The version of the OpenAPI document/d'
	$(call rename,DataValueOneOf1,DVText)
	$(call rename,DataValueOneOf,DVInt)
	$(call rename,SharedParamValueOneOf1,SPVList)
	$(call rename,SharedParamValueOneOf,SPVOne)
	$(call rename,WarningOneOf1,WarningRevealPrivacy)
	$(call rename,WarningOneOf,WarningUnsupportedFeature)

.PHONY: compile-install-generated
compile-install-generated:
	cd $(CODE_GEN_DIR); mvn clean install

.PHONY: compile-install-generated
compile-example:
	mvn clean
	mvn compile

.PHONY: run-ac2c
run-ac2c: reset-db
	mvn exec:java -Dexec.args="AC2C"

.PHONY: run-dnc
run-dnc: reset-db
	mvn exec:java -Dexec.args="DNC"

.PHONY: test-revealed
test-revealed: reset-db
	mvn test -Dtest="AppTest#testRevealed"

.PHONY: test-equalities
test-equalities: reset-db
	mvn test -Dtest="AppTest#testEqualities"

.PHONY: test-range
test-range: reset-db
	mvn test -Dtest="AppTest#testRange"

.PHONY: test-verifiable-encryption-ac2c
test-verifiable-encryption-ac2c: reset-db
	mvn test -Dtest="AppTest#testVerifiableEncryptionAC2C"

.PHONY: test-verifiable-encryption-dnc
test-verifiable-encryption-dnc: reset-db
	mvn test -Dtest="AppTest#testVerifiableEncryptionDNC"

.PHONY: test-accumulators
test-accumulators: reset-db
	mvn test -Dtest="AppTest#testAccumulators"

.PHONY: test-all
test-all: reset-db
	mvn test

.PHONY: test-all-except-verifiable-encryption-dnc
test-all-except-verifiable-encryption-dnc: reset-db
	make test-revealed
	make test-equalities
	make test-accumulators
	make test-range

.PHONY: clean
clean: reset-db
	mvn clean

.PHONY: really-clean
really-clean: reset-db
	mvn clean
	rm -rf ~/.m2/repository/$(COM_slash_EXAMPLE_slash_VCP)/$(ARTIFACT_ID)

.PHONY: reset-db
reset-db:
	rm   -rf /tmp/AccumulatorTmpData
	mkdir -p /tmp/AccumulatorTmpData
