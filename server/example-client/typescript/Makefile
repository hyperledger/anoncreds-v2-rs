# These MUST be defined before the includes.
LANGUAGE = typescript-fetch
GEN_DIR  = ./generated

GENERATE_CONFIG = \
  --enum-name-mappings DVInt=DV_INT,DVText=DV_TEXT \
  --enum-name-mappings SPVOne=SPV_ONE,SPVList=SPV_LIST \
  --enum-name-mappings UNSUPPORTEDFEATURE=UNSUPPORTED_FEATURE \
  --enum-name-mappings REVEALPRIVACYWARNING=REVEAL_PRIVACY_WARNING

include ./Makefile-openapi

# Sum types (e.g., DataValue) get generated as a base class (e.g., DataValue.java)
# and a class for each variants.  But the class names are, e.g., DataValueOneOf, DataValueOneOf1, ...
# So, for ease of use, the class and all references to them are renamed (e.g., DVInt, DVText).
# This is done via the rename Makefile canned recipe, that renames generated files via `mv`
# and renames references to them in all files via `sed`.

define rename
	mv   $(CODE_GEN_DIR)/models/$1.ts \
             $(CODE_GEN_DIR)/models//$2.ts
	find $(CODE_GEN_DIR) -name "*.ts" -type f \
             | xargs sed -i 's/$1/$2/g'
endef

.PHONY: tweak-generated-code
tweak-generated-code:
	$(call rename,DataValueOneOf1,DVText)
	$(call rename,DataValueOneOf,DVInt)
	$(call rename,SharedParamValueOneOf1,SPVList)
	$(call rename,SharedParamValueOneOf,SPVOne)
	$(call rename,WarningOneOf1,WarningRevealPrivacy)
	$(call rename,WarningOneOf,WarningUnsupportedFeature)

.PHONY: generated-package
generated-package:
	cp package.json-for-generated-code $(CODE_GEN_DIR)/package.json

.PHONY: generated-config
generated-config:
	cp tsconfig.json-for-generated-code $(CODE_GEN_DIR)/tsconfig.json

.PHONY: compile-install-generated
 compile-install-generated: generated-package generated-config
	cd $(CODE_GEN_DIR); pnpm install && pnpm build
	pnpm install $(CODE_GEN_DIR) --save

.PHONY: build
build:
	pnpm build

.PHONY: test
test:
	pnpm run test

.PHONY: test-revealed
test-revealed:
	pnpm run test --revealed

.PHONY: test-equalities
test-equalities:
	pnpm run test --equalities

.PHONY: test-accumulators
test-accumulators:
	pnpm run test --accumulators

.PHONY: test-range
test-range:
	pnpm run test --predicates

.PHONY: test-verifiable-encryption
test-verifiable-encryption:
	pnpm run test --verifiable-encryption

.PHONY: test-verifiable-encryption-dnc-non-blinded
test-verifiable-encryption-dnc-non-blinded:
	pnpm run test --verifiable-encryption-dnc-non-blinded

.PHONY: test-verifiable-encryption-dnc-blinded
test-verifiable-encryption-dnc-blinded:
	pnpm run test --verifiable-encryption-dnc-blinded

.PHONY: clean
clean:
	pnpm clean

