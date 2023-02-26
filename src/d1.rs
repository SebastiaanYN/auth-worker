use serde::Deserialize;
use worker::{
    console_error,
    js_sys::{Array, ArrayBuffer, Object, Reflect, Uint8Array},
    wasm_bindgen::{JsCast, JsValue},
    wasm_bindgen_futures::JsFuture,
    Result,
};

mod sys {
    use worker::js_sys::{Array, Object, Promise};
    use worker::wasm_bindgen::{self, prelude::*};

    #[wasm_bindgen]
    extern "C" {
        #[derive(Debug, Clone)]
        pub type QueryResult;

        #[wasm_bindgen(structural, method, getter, js_name=results)]
        pub fn results(this: &QueryResult) -> Option<Array>;

        #[wasm_bindgen(structural, method, getter, js_name=success)]
        pub fn success(this: &QueryResult) -> bool;

        #[wasm_bindgen(structural, method, getter, js_name=error)]
        pub fn error(this: &QueryResult) -> Option<String>;

        #[wasm_bindgen(structural, method, getter, js_name=meta)]
        pub fn meta(this: &QueryResult) -> Object;
    }

    #[wasm_bindgen]
    extern "C" {
        #[derive(Debug, Clone)]
        pub type ExecResult;

        #[wasm_bindgen(structural, method, getter, js_name=count)]
        pub fn count(this: &ExecResult) -> Option<u32>;

        #[wasm_bindgen(structural, method, getter, js_name=time)]
        pub fn time(this: &ExecResult) -> Option<f64>;
    }

    #[wasm_bindgen]
    extern "C" {
        #[wasm_bindgen(extends=worker::js_sys::Object, js_name=D1Database)]
        #[derive(Debug, Clone, PartialEq, Eq)]
        pub type Database;

        #[wasm_bindgen(structural, method, js_class=D1Database, js_name=prepare)]
        pub fn prepare(this: &Database, query: &str) -> PreparedStatement;

        #[wasm_bindgen(structural, method, js_class=D1Database, js_name=dump)]
        pub fn dump(this: &Database) -> Promise;

        #[wasm_bindgen(structural, method, js_class=D1Database, js_name=batch)]
        pub fn batch(this: &Database, statements: Array) -> Promise;

        #[wasm_bindgen(structural, method, js_class=D1Database, js_name=exec)]
        pub fn exec(this: &Database, query: &str) -> Promise;
    }

    #[wasm_bindgen]
    extern "C" {
        #[wasm_bindgen(extends=worker::js_sys::Object, js_name=D1PreparedStatement)]
        #[derive(Debug, Clone, PartialEq, Eq)]
        pub type PreparedStatement;

        #[wasm_bindgen(structural, method, catch, variadic, js_class=D1PreparedStatement, js_name=bind)]
        pub fn bind(this: &PreparedStatement, values: Array) -> Result<PreparedStatement, JsValue>;

        #[wasm_bindgen(structural, method, js_class=D1PreparedStatement, js_name=first)]
        pub fn first(this: &PreparedStatement, col_name: Option<&str>) -> Promise;

        #[wasm_bindgen(structural, method, js_class=D1PreparedStatement, js_name=run)]
        pub fn run(this: &PreparedStatement) -> Promise;

        #[wasm_bindgen(structural, method, js_class=D1PreparedStatement, js_name=all)]
        pub fn all(this: &PreparedStatement) -> Promise;

        #[wasm_bindgen(structural, method, js_class=D1PreparedStatement, js_name=raw)]
        pub fn raw(this: &PreparedStatement) -> Promise;
    }
}

// A D1 Database.
pub struct Database(sys::Database);

impl Database {
    /// Prepare a query statement from a query string.
    pub fn prepare<T: Into<String>>(&self, query: T) -> PreparedStatement {
        self.0.prepare(&query.into()).into()
    }

    /// Dump the data in the database to a `Vec`.
    pub async fn dump(&self) -> Result<Vec<u8>> {
        let array_buffer = JsFuture::from(self.0.dump()).await?;
        let array_buffer = array_buffer.dyn_into::<ArrayBuffer>()?;
        let array = Uint8Array::new(&array_buffer);
        let mut vec = Vec::with_capacity(array.length() as usize);
        array.copy_to(&mut vec);
        Ok(vec)
    }

    /// Batch execute one or more statements against the database.
    ///
    /// Returns the results in the same order as the provided statements.
    pub async fn batch(&self, statements: Vec<PreparedStatement>) -> Result<Vec<QueryResult>> {
        let statements = statements.into_iter().map(|s| s.0).collect::<Array>();
        let results = JsFuture::from(self.0.batch(statements)).await?;
        let results = results.dyn_into::<Array>()?;
        let mut vec = Vec::with_capacity(results.length() as usize);
        for result in results.iter() {
            let result = result.dyn_into::<sys::QueryResult>()?;
            vec.push(QueryResult(result));
        }
        Ok(vec)
    }

    /// Execute one or more queries directly against the database.
    ///
    /// The input can be one or multiple queries separated by `\n`.
    ///
    /// # Considerations
    ///
    /// This method can have poorer performance (prepared statements can be reused
    /// in some cases) and, more importantly, is less safe. Only use this
    /// method for maintenance and one-shot tasks (example: migration jobs).
    ///
    /// If an error occurs, an exception is thrown with the query and error
    /// messages, execution stops and further statements are not executed.
    pub async fn exec(&self, query: &str) -> Result<sys::ExecResult> {
        let result = JsFuture::from(self.0.exec(query)).await?;
        Ok(result.into())
    }
}

impl JsCast for Database {
    fn instanceof(val: &JsValue) -> bool {
        val.is_instance_of::<sys::Database>()
    }

    fn unchecked_from_js(val: JsValue) -> Self {
        Self(val.into())
    }

    fn unchecked_from_js_ref(val: &JsValue) -> &Self {
        unsafe { &*(val as *const JsValue as *const Self) }
    }
}

impl From<Database> for JsValue {
    fn from(database: Database) -> Self {
        JsValue::from(database.0)
    }
}

impl AsRef<JsValue> for Database {
    fn as_ref(&self) -> &JsValue {
        &self.0
    }
}

impl From<sys::Database> for Database {
    fn from(inner: sys::Database) -> Self {
        Self(inner)
    }
}

// A D1 prepared query statement.
pub struct PreparedStatement(sys::PreparedStatement);

impl PreparedStatement {
    /// Bind one or more parameters to the statement. Returns a new statement object.
    ///
    /// D1 follows the SQLite convention for prepared statements parameter binding.
    ///
    /// # Considerations
    ///
    /// Supports Ordered (?NNNN) and Anonymous (?) parameters - named parameters are currently not supported.
    ///
    pub fn bind(&self, values: &[JsValue]) -> Result<Self> {
        let array: Array = values.into_iter().collect::<Array>();

        match self.0.bind(array) {
            Ok(stmt) => Ok(PreparedStatement(stmt)),
            Err(err) => {
                #[derive(Deserialize)]
                struct Cause {
                    cause: String,
                }
                let cause = serde_wasm_bindgen::from_value::<Cause>(err.clone())
                    .unwrap()
                    .cause;
                console_error!("bind cause {cause}");
                Err(worker::Error::from(err))
            }
        }
    }

    /// Return the first row of results.
    ///
    /// If `col_name` is `Some`, returns that single value, otherwise returns the entire object.
    ///
    /// If the query returns no rows, then this will return `None`.
    ///
    /// If the query returns rows, but column does not exist, then this will return an `Err`.
    pub async fn first<T>(&self, col_name: Option<&str>) -> Result<Option<T>>
    where
        T: for<'a> Deserialize<'a>,
    {
        let js_value = JsFuture::from(self.0.first(col_name)).await?;
        let value = serde_wasm_bindgen::from_value(js_value)
            .map_err(|e| worker::Error::Internal(e.into()))?;
        Ok(value)
    }

    /// Executes a query against the database but only return metadata.
    pub async fn run(&self) -> Result<QueryResult> {
        let result = JsFuture::from(self.0.run()).await.map_err(|e| {
            #[derive(Deserialize)]
            struct Cause {
                cause: String,
            }
            let cause = serde_wasm_bindgen::from_value::<Cause>(e.clone())
                .unwrap()
                .cause;
            console_error!("run cause {cause}");
            e
        })?;
        Ok(QueryResult(result.into()))
    }

    /// Executes a query against the database and returns all rows and metadata.
    pub async fn all(&self) -> Result<QueryResult> {
        let result = JsFuture::from(self.0.all()).await?;
        Ok(QueryResult(result.into()))
    }

    /// Executes a query against the database and returns a `Vec` of rows instead of objects.
    pub async fn raw<T>(&self) -> Result<Vec<Vec<T>>>
    where
        T: for<'a> Deserialize<'a>,
    {
        let result = JsFuture::from(self.0.raw()).await?;
        let result = result.dyn_into::<Array>()?;
        let mut vec = Vec::with_capacity(result.length() as usize);
        for value in result.iter() {
            let value = serde_wasm_bindgen::from_value(value)
                .map_err(|e| worker::Error::Internal(e.into()))?;
            vec.push(value);
        }
        Ok(vec)
    }
}

impl From<sys::PreparedStatement> for PreparedStatement {
    fn from(inner: sys::PreparedStatement) -> Self {
        Self(inner)
    }
}

// The result of a D1 query execution.
#[derive(Debug)]
pub struct QueryResult(sys::QueryResult);

impl QueryResult {
    /// Returns `true` if the result indicates a success, otherwise `false`.
    pub fn success(&self) -> bool {
        self.0.success()
    }

    /// Return the error contained in this result.
    ///
    /// Returns `None` if the result indicates a success.
    pub fn error(&self) -> Option<String> {
        self.0.error()
    }

    /// Retrieve the collection of result objects, or an `Err` if an error occurred.
    pub fn results<T>(&self) -> Result<Vec<T>>
    where
        T: for<'a> Deserialize<'a>,
    {
        if let Some(results) = self.0.results() {
            let mut vec = Vec::with_capacity(results.length() as usize);
            for result in results.iter() {
                let result = serde_wasm_bindgen::from_value(result)
                    .map_err(|e| worker::Error::Internal(e.into()))?;
                vec.push(result);
            }
            Ok(vec)
        } else {
            Ok(Vec::new())
        }
    }
}

pub fn binding(env: &worker::Env, name: &str) -> Result<Database> {
    const TYPE_NAME: &str = "D1Database";

    let binding = Reflect::get(env, &JsValue::from(name))
        .map_err(|_| worker::Error::JsError(format!("Env does not contain binding `{}`", name)))?;
    if binding.is_undefined() {
        Err(format!("Binding `{}` is undefined.", name).into())
    } else {
        // Can't just use JsCast::dyn_into here because the type name might not be in scope
        // resulting in a terribly annoying javascript error which can't be caught
        let obj = Object::from(binding);
        if obj.constructor().name() == TYPE_NAME {
            Ok(obj.unchecked_into())
        } else {
            Err(format!(
                "Binding cannot be cast to the type {} from {}",
                TYPE_NAME,
                obj.constructor().name()
            )
            .into())
        }
    }
}

macro_rules! query {
    ($db:expr, $query:expr) => {
        $crate::d1::Database::prepare($db, $query)
    };
    ($db:expr, $query:expr, $($args:expr),* $(,)?) => {{
        || -> ::std::result::Result<$crate::d1::PreparedStatement, ::worker::Error> {
            let prepared = $crate::d1::Database::prepare($db, $query);

            // D1 does not accept undefined as NULL
            let serializer = ::serde_wasm_bindgen::Serializer::new().serialize_missing_as_null(true);
            let bindings = &[$(
                ::serde::ser::Serialize::serialize(&$args, &serializer)
                    .map_err(|e| ::worker::Error::Internal(e.into()))?
            ),*];

            $crate::d1::PreparedStatement::bind(&prepared, bindings)
        }()
    }};
}

pub(crate) use query;
