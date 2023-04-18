---
# try also 'default' to start simple
theme: 'dracula'
# random image from a curated Unsplash collection by Anthony
# like them? see https://unsplash.com/collections/94734566/slidev
background: https://source.unsplash.com/collection/94734566/1920x1080
# apply any windi css classes to the current slide
class: 'text-center'
# https://sli.dev/custom/highlighters.html
highlighter: shiki
# show line numbers in code blocks
lineNumbers: false
# persist drawings in exports and build
drawings:
  persist: false
# use UnoCSS
css: unocss
---

# OAuth2 and OpenID Connect

<br />
<br />

## NodeJS implementation of the OAuth2 Code flow

---

# Client Registration

<div class="grid grid-rows-1 grid-cols-3 centered-grid">

  <EntityLane title="Client" />

  <div class="grid grid-rows-2 grid-cols-1 centered-grid">

  <div v-click="1">

  **POST** http://auth_server.com/client

  ```json
  {
    "applicationName": "test-app",
    "redirectUrls": ["http://localhost:2346/auth_callback"]
  }
  ```
  
  <ic-baseline-keyboard-double-arrow-right class="text-5xl" style="float: right"/>

  </div>

  <div v-click="2">

  **201**
  ```json
  {
      "clientId": "generateUUIDv1()",
      "clientSecret": "generateRandomHexString(64)"
  }
  ```
  </div>
  </div>

  <EntityLane title="Authorization Server" />

</div>

---

# The Client Starts the Code Flow

<div class="grid grid-rows-3 grid-cols-1 centered-grid">

  <div v-click="1">

  ```
  GET http://client.com/start_oauth?callbackRoute=/auth_callback&scope=openid+contacts.read+profile.read
  ```
  </div>

  <div v-click="2">
  | Query Param | Description |
  | ----------- | ----------- |
  | callbackRoute | The redirect uri |
  
  </div>

  <div v-click="3">

  **302** 
  
  Location: http://auth_server.com/oauth/authorize/...
  </div>
</div>

---

<!-- # The Client Start the Code Flow

<div class="grid grid-cols-6 centered-grid">
  <img src="https://cf.geekdo-static.com/images/logos/navbar-logo-bgg-b2.svg" />
  <material-symbols-arrow-forward-ios-rounded class="text-4xl"/>
  <div class="col-span-4 text-sm">

  | Field | Description | How |
  | ----- | ----------- | ---- |
  | **Id** | The BGG Id of the boardgame | XMLAPI2 |
  | **Name** | The boardgame name | XMLAPI2 |
  | **Averageweight** | The average of the complexity scores given by the user | XMLAPI2 |
  | **Playingtime** | The playing time | XMLAPI2 |
  | **Family** | List of the boardgame's categories, like family game, strategy, etc | XMLAPI2 |
  | **Rulebook** | The boardgame's rulebook | Internal APIs |

  </div>
</div>

### *XMLAPI2: https://boardgamegeek.com/wiki/page/BGG_XML_API2*

---
clicks: 8
---

# Rulebook Download

How to automate the rulebooks' download? **No public APIs** and often **many documents to choose from**

<div v-if="$slidev.nav.clicks >= 0 && $slidev.nav.clicks <= 4">

- Internal APIs for authenticated users

```python {all|2|6|17|all}
async def get_bgg_filelist(client, thing_id: int) -> List[BoardGameFileInfo]:
    url = f"https://api.geekdo.com/api/files?ajax=1&nosession=1&objectid={thing_id}&objecttype=thing&pageid=1&showcount=25&sort=hot&languageid=2184"
    async with client.get(url) as response:
        content = await response.json()
        files = content['files']
        file_list = filter(lambda x: x is not None and x.extension == 'pdf', [BoardGameFileInfo.from_file_info(file) for file in files])
        return file_list

async def get_file_content(client, auth_token: str, file: BoardGameFileInfo) -> str:
    url = f'https://api.geekdo.com/api/files/downloadurls?ids={file.id}' 
    headers = { 'Authorization': f'GeekAuth {auth_token}' }
    async with RetryingClientResponse(lambda: client.get(url, headers=headers)) as response:
        content = await response.json()        
        download_url = 'https://boardgamegeek.com' + content['downloadUrls'][0]['url']
        async with RetryingClientResponse(lambda: client.get(download_url)) as pdf_response:
            pdf_data = await pdf_response.read()
            with PyMuPDF.open(stream=pdf_data, filetype="pdf") as doc:
                # return parsed file
```

</div>

<div v-if="$slidev.nav.clicks >= 5 && $slidev.nav.clicks <= 8">

- Search engine based on Tf-Idf to choose the best document

```python {|||||all|2|4|all}
filelist = await get_bgg_filelist(client, thing_id)
doc_vectors = vectorizer.fit_transform(f'{x.name} {x.plain_description}' for x in filelist)

query_vector = vectorizer.transform(["revised official rule rulebook update new"])
docs_ranked = cosine_similarity(query_vector, doc_vectors)

# ... Take only the best doc
```

</div>

---

# Data Cleaning

- The Family field is one-hot encoded 

<div class="grid grid-rows-1 grid-cols-3 centered-grid" v-click>

  ```
  1. ["familygame", "strategy"]
  2. []
  3. ["abstract", "strategy"]
  ```

  <ic-outline-arrow-circle-right class="text-4xl" />

  | familygame | strategy | abstract | unspecified |
  | ---------- | -------- | -------- | ----------- |
  | 1 | 1 | 0 | 0 |
  | 0 | 0 | 0 | 1 |
  | 0 | 1 | 1 | 0 |

</div>

---
clicks: 10
---

# Rulebook Cleaning

<div v-if="$slidev.nav.clicks >= 0 && $slidev.nav.clicks <= 8">

- By regular expressions to:

  <v-clicks>

    - Remove mails and links
    - Keep sentences longer than 4 words, where each word has at least 2 chars
    - Clearly separate sentences (e.g. "*first sentence.Second one*" <material-symbols-arrow-right-alt-rounded /> "*first sentence. Second one*")
    - Compress consecutive whitespaces
    - Join interrupted word parts (e.g. "*Infor- mation*" <material-symbols-arrow-right-alt-rounded /> "*Information*")
    - Remove characters around numbers (e.g. *"-----12-----"* could be a page number)
    - Recover missing apices (e.g. "*can t*" <material-symbols-arrow-right-alt-rounded /> "*can't*")
    - ...
  </v-clicks>
</div>

<div v-if="$slidev.nav.clicks >= 9 && $slidev.nav.clicks <= 10">

- By Coreference Resolution (with `coreferee`)
  <div class="grid grid-rows-1 grid-cols-3 centered-grid">

    <div v-click="9">

    *Although <span class="text-red-600">he</span> was very busy with <span class="text-red-600">his</span> <span class="text-green-600">work</span>, <span class="text-red-600">Peter</span> had had enough of <span class="text-green-600">it</span>.*
    </div>
    
    <div v-click="10" class="col-span-2 centered-flex">
    <ic-outline-arrow-circle-right class="text-4xl centered-arrow"/>
    
    *Although <span class="text-red-600">Peter</span> was very busy with <span class="text-red-600">Peter</span> <span class="text-green-600">work</span>, <span class="text-red-600">Peter</span> had had enough of <span class="text-green-600">work</span>.*
    </div>
  </div>
</div>

---

# The BoardgameGeek Weight

<br />
<div v-click>
  <div class="barContainer">
    <span class="bar1 bar"></span>
    <span class="bar2 bar"></span>
    <span class="bar3 bar"></span>
    <span class="bar4 bar"></span>
    <span class="bar5 bar"></span>
  </div>

  <span style="margin-left: 5%">0</span>
  <span style="float: right; margin-right: 5%">5</span>
</div>
<br />

<div v-click>

- Amount of rules ✅
- Gameplay length ✅
- Amount of luck ✅
- Technical skill required (math, planning, reading, etc.) 🟡
- Amount of choices available ✅
- Amount of bookkeeping ❌
- Level of difficulty ❓

### *Source: https://boardgamegeek.com/wiki/page/Weight*

</div>

<style>
  .barContainer { width: 90%; margin-left: 5%; float: left; }
  .barContainer span { 
    display: inline-block; 
    float: left;
    min-height: 1em;
  }
  .bar { width: 25% }
  .bar1 { 
    background: rgb(102,255,102);
    background: linear-gradient(90deg, rgba(102,255,102,1) 0%, rgba(178,255,102,1) 100%); 
  }
  .bar2 { 
    background: rgb(178,255,102);
    background: linear-gradient(90deg, rgba(178,255,102,1) 0%, rgba(255,255,102,1) 100%); 
  }
  .bar3 { 
    background: rgb(255,255,102);
    background: linear-gradient(90deg, rgba(255,255,102,1) 0%, rgba(255,178,102,1) 100%);
  }
  .bar4 { 
    background: rgb(255,178,102);
    background: linear-gradient(90deg, rgba(255,178,102,1) 0%, rgba(255,102,102,1) 100%);
  }
</style>

---
clicks: 13
---

# Amount of Luck

Main sources of luck:

<div v-if="$slidev.nav.clicks >= 0 && $slidev.nav.clicks <= 3">

Shuffling a deck, or when *"random/randomly"* words are used

```python {all|4|11|all}
# ---------- random ----------
random_matcher = Matcher(doc.vocab)
random_patterns_match = [
    [{"LEMMA": { "IN": ["random", "randomly"]}}]
]
random_matcher.add("random", random_patterns_match)

# ---------- shuffle ----------
shuffle_matcher = Matcher(doc.vocab)
shuffle_patterns_match = [
    [{"LEMMA": "shuffle"}]
]
shuffle_matcher.add("shuffle", shuffle_patterns_match)
```
</div>

<div v-if="$slidev.nav.clicks >= 4 && $slidev.nav.clicks <= 7">

Drawing a card

```python {||||all|6|13-15|all}
g_matcher = DependencyMatcher(doc.vocab)    
drawing_patterns = [
    [
        {
            "RIGHT_ID": "drawing",
            "RIGHT_ATTRS": {"LEMMA": "draw", "POS": "VERB"}
        },
        {
            "LEFT_ID": "drawing",
            "REL_OP": ">",
            "RIGHT_ID": "card",
            "RIGHT_ATTRS": {
                "LEMMA": "card",
                "POS": "NOUN", 
                "DEP": { "IN": ['dobj', 'nsubjpass', 'compound'] }
            }
        }
    ]
]
```
</div>

<div v-if="$slidev.nav.clicks >= 8 && $slidev.nav.clicks <= 13">

Rolling a die

```python {||||||||all|6|13-15|22|29,30|all}
dice_matcher = DependencyMatcher(doc.vocab)    
dice_patterns = [
    [
        {
            "RIGHT_ID": "rolling",
            "RIGHT_ATTRS": {"LEMMA": { "IN": ["use", "throw", "roll"]}, "POS": "VERB"}
        },
        {
            "LEFT_ID": "rolling",
            "REL_OP": ">",
            "RIGHT_ID": "dice_or_die",
            "RIGHT_ATTRS": {
                "LEMMA": { "IN": ["die", "dice"]},
                "POS": "NOUN", 
                "DEP": { "IN": ['nsubj', 'dobj', 'nsubjpass', 'compound'] }
            }
        }
    ],
    [
        {
            "RIGHT_ID": "rolling",
            "RIGHT_ATTRS": {"LEMMA": { "IN": ["use", "throw", "roll"]}, "POS": "VERB"}
        },
        {
            "LEFT_ID": "rolling",
            "REL_OP": ">",
            "RIGHT_ID": "number",
            "RIGHT_ATTRS": {
                "IS_DIGIT": True, 
                "DEP": { "IN": ['dobj'] }
            }
        }
    ]
]
dice_matcher.add("diceroll", dice_patterns)
```
</div>

---
clicks: 5
---

# Technical skill required (math, planning, reading)

<v-clicks>

- Math ❌
- Planning ❌
- Reading ✅

</v-clicks>

<br />
<div v-click="4"> 
  
  **MTLD** (Measure of Textual Lexical Diversity)
</div>

<div v-click="5"> 

  - Mostly independent from text length
  - Highly sensitive
  - Based on TTR (Type-Token ratio)
</div>

---
clicks: 10
---

# Amount of choices available

<div v-if="$slidev.nav.clicks >= 0 && $slidev.nav.clicks <= 4">

Modal verbs like *can/could/may/select/choose* or nouns like *choice/option*

```python {all|1-6|8-13|15-20|all}
can_could_may_patterns = [
    [{
        "LEMMA": { "IN": ["can", "could", "may"]}, 
        "POS": "AUX"
    }]
]
# ...
choose_patterns = [
    [{
        "LEMMA": { "IN": ["decide", "select", "choose", "opt"]}, 
        "POS": "VERB"
    }]
]
# ...
choice_option_patterns = [
    [{
        "LEMMA": { "IN": ["choice", "option"]}, 
        "POS": "NOUN"
    }]
]
```
</div>

<div v-if="$slidev.nav.clicks === 5">

It is not always true...

- cannot + verb <material-symbols-arrow-right-alt-rounded /> Impossibility to do something
- can + choose to + verb <material-symbols-arrow-right-alt-rounded /> Should be counted as 1 choice
- no + choice <material-symbols-arrow-right-alt-rounded /> No actual choice
- ...

</div>

<div v-if="$slidev.nav.clicks >= 6">

Subtract the tokens found for these exceptions from the initial ones, for example

```python {||||||all|5,6|14|22,23|all}
# ❌ can not/only/never verb 
{
    "RIGHT_ID": "can_could_may",
    "RIGHT_ATTRS": {
        "LEMMA": { "IN": ["can", "could", "may"]}, 
        "POS": "AUX"
    }
},
{
    "LEFT_ID": "can_could_may",
    "REL_OP": "<",
    "RIGHT_ID": "generic_verb",
    "RIGHT_ATTRS": {
        "POS": { "IN": ["AUX", "VERB"] }
    }
},
{
    "LEFT_ID": "generic_verb",
    "REL_OP": ">",
    "RIGHT_ID": "neg_or_only",
    "RIGHT_ATTRS": {
        "LEMMA": { "IN": ["not", "only", "never"]}, 
        "DEP": { "IN": ["advmod", "neg"] }
    }
}
```

</div>

---

# Entities

<v-clicks>

Boardgame complexity ∝ Entities

Entity = *Any necessary noun that makes a rule meaningful*

<div>
According to this definition, an entity can be:

- The game materials
- A phase of the game
- A resource type, like in a Eurogame
</div>

</v-clicks>

---

# How to Find Entities?

<v-clicks>

<div>

- Keyword Extraction? ❌
  * Too many "garbage" words
</div>
<div>

- `Spacy` Named Entities? ❌
  * Good for real-world object, not for this type of entity
</div>
<div>

- `Spacy` Linguistic Features ✅
  * Part-of-Speech
  * Dependency Tree
</div>

</v-clicks>

---
clicks: 10
---

# Entity Retrieval with `Spacy`

<div v-if="$slidev.nav.clicks <= 4">

- Create a dictionary of filtered nouns

```python {all|5|6|7|all}
def find_most_common_nouns(doc: spacy.tokens.Doc) -> Dict[str, List[spacy.tokens.Token]]:
    tokens_dict = defaultdict(list)

    for token in doc:
        if len(token) >= 3 and \
            token.pos_ in {'NOUN', 'PROPN'} and \
            token.dep_ in {'nsubj', 'dobj', 'nsubjpass', 'pobj'}:
            tokens_dict[token.lemma_.lower()].append(token)
           
    return tokens_dict
```    

</div>

<div v-if="$slidev.nav.clicks >= 5">

- Keep only the nouns that satisfy the following conditions

```python {|||||all|5|6|7,8|9-11|all}
def _is_token_an_unigram(token_info: Tuple[str, List[spacy.tokens.Token]]) -> bool:
    token = token_info[0]
    occurrences = token_info[1]
    sentence_ids = sorted([occ._.sentence_id for occ in occurrences])
    return token not in IGNORED_WORDS and \
            len(occurrences) >= MIN_TOKEN_TO_BE_CONSIDERED_UNIGRAM and \
            any(token_occurrence.dep_ in {'nsubj', 'nsubjpass', 'dobj'} \
                for token_occurrence in occurrences) and \
            min( # get the minimum distance between sentence ids. A token must not be completely sparse 
                map(lambda x: x[1] - x[0], zip(sentence_ids[:-1], sentence_ids[1:]))
            ) <= MAX_DISTANCE_TO_BE_CONSIDERED_UNIGRAM
```

</div>

---

# Entity-based Metrics

<v-clicks>

- Entity count
- Actions score
- Interactions score
- Entities variance

</v-clicks>

---

# Actions Score

**How many ways can an entity affect the game?**

```python {all|3,4|9|all}
def find_actions_count_for_unigrams(doc: spacy.tokens.Doc, 
                                    unigrams: Dict[str, List[spacy.tokens.Token]]) -> Dict[str, int]:
    return { unigram: len(set(token.head.lemma_ for token in unigrams[unigram] if token.head.pos_ == 'VERB'))
        for unigram in unigrams }

def get_actions_score(doc: spacy.tokens.Doc, 
                      unigrams: Dict[str, List[spacy.tokens.Token]]) -> float:
    actions_counts = find_actions_count_for_unigrams(doc, unigrams)
    return sum(unigram_action_count[1] for unigram_action_count in actions_counts.items()) / len(unigrams)
```

---

# Interactions Score

**How complex is an entity?**

Where *complex* refers to the initial definition of complexity

<div class="grid grid-cols-2">
<v-click>
  <div id="interactions-grid" class="grid grid-cols-5">

  <div class="bordercell"></div>
  <div class="bordercell">e1</div>
  <div class="bordercell">e2</div>
  <div class="bordercell">e3</div>
  <div class="bordercell">e4</div>

  <div class="bordercell">e1</div>
  <OpaqueGridCell value=0 />
  <OpaqueGridCell value=10 />
  <OpaqueGridCell value=6 />
  <OpaqueGridCell value=3 />

  <div class="bordercell">e2</div>
  <OpaqueGridCell value=0 />
  <OpaqueGridCell value=0 />
  <OpaqueGridCell value=6 />
  <OpaqueGridCell value=0 />

  <div class="bordercell">e3</div>
  <OpaqueGridCell value=0 />
  <OpaqueGridCell value=0 />
  <OpaqueGridCell value=0 />
  <OpaqueGridCell value=6 />

  <div class="bordercell">e4</div>
  <OpaqueGridCell value=0 />
  <OpaqueGridCell value=0 />
  <OpaqueGridCell value=0 />
  <OpaqueGridCell value=0 />

  </div>
</v-click>

<v-click>
  <div>
  The Interactions score is the density of the sparse graph represented by the matrix
  <br />
  <br />

  <div style="width: 100%; justify-content: center; display: flex">

  $η = \frac{2|E|}{|V|(|V|−1)}$
  </div>
  </div>
</v-click>
</div>

<style>
  #interactions-grid {
    width: 90%;
    .bordercell {
      text-align: center;
      padding: 20%;
      border: 1px solid grey;
    }
  }

  .katex {
    font-size: 2em;
  }
</style>

---

# Entities Variance

**How scattered are the entities in the text?**

<br />
<br />
<v-click>

  <div style="width: 100%; justify-content: center; display: flex">

  $\frac{\sum_{i = 0}^{len(entities)} \frac{len(entity_i)}{len(all\ entities)} * np.var([entity.sentence\_id\ for\ entity\ in\ entities_i])}{len(sentences)}$
  </div>

</v-click>

<style>
  .katex {
    font-size: 2em;
  }
</style>

---

# Model Training

<v-clicks>

- **Preprocessing**: `RobustScaler` usually gives the best results, but `StandardScaler` and `MinMaxScaler` are good as well
- **Feature Selection**: `RFECV` for coefficient-based models, `SelectKBest` for the others
- **Best Model**: `SVR`
- **MAE** ≈ `0.30`
- **Learning Curve**: stable after a dataset of 150 boardgames
- **K-Best Features**: between 6 and 13, depending on the model. 7 for `SVR`

</v-clicks>

---

# Best Features

For `SVR`, on 5 trainings with different train-test splits, the chosen features are:

`['playingtime', 'rulebook_len', 'entities_count', 'interaction_score', 'entities_variance', 'actions_score', 'familygames', 'strategygames']`

<br />
<br />

<v-click>
<div>
<fa-exclamation-triangle style="color: yellow"/> 
The metrics computed specifically for the BGG Weight are not relevant (in SVR)
</div>
</v-click>

---

# Features Weight

With `SVR`, features do not have coefficients associated, but we can use the `permutation_importance` method to find the features that, when randomized, mostly affect the predictions

<v-click>

```
playingtime         0.664 +/- 0.045
rulebook_len        0.150 +/- 0.017
strategygames       0.146 +/- 0.014
entities_count      0.107 +/- 0.011
entities_variance   0.095 +/- 0.010
familygames         0.063 +/- 0.008
actions_score       0.036 +/- 0.006
```
</v-click>

---

# Future Work

<div class="grid grid-cols-3 centered-grid gap-y-3" style="justify-items: initial">

  <div v-click>
    <fa-exclamation-triangle style="color: red"/>
    Rulebooks downloaded are not always correct
  </div>

  <div v-click class="col-span-2 centered-flex">
    <material-symbols-arrow-right-alt-rounded class="centered-arrow"/>
    Analyze multiple rulebooks of the same boardgame and decide which is the best, remove unnecessary paragraph while cleaning 
  </div>

  <div v-click>
    <fa-exclamation-triangle style="color: red"/>
    The entity search algorithm is "static"
  </div>

  <div v-click class="col-span-2 centered-flex">
    <material-symbols-arrow-right-alt-rounded class="centered-arrow"/> 
    Remove static thresholds, rank the entities and choose the top ones dynamically
  </div>

  <div v-click>
    <fa-exclamation-triangle style="color: red"/>
    Boardgame depth
  </div>

  <div v-click class="col-span-2 centered-flex">
    <material-symbols-arrow-right-alt-rounded class="centered-arrow"/> 
    Integrate the rulebook with other resources and info
  </div> 
</div> -->