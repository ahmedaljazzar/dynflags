import React from 'react';

import {List, Skeleton} from 'antd';
import axios from 'axios';

import './App.css';


const featuresUrl = ` https://vdjkrpkd25gzpntxj3l5o6zjsy.appsync-api.us-west-2.amazonaws.com/graphql`;
const apiKey = `da2-hgnlfakeana7vdw7kfuj6l5pkq`;

class App extends React.Component {
    state = {
        loading: true,
        data: [],
        list: [],
    };

    componentDidMount() {
        this.getData(res => {
            var list = res.data.data.getGlobals;

            this.setState({
                loading: false,
                data: list,
                list: list,
            });
        });
    }

    getData = async (callback) => {
        const query = 'query { getGlobals }';
        const variables = {};

        await axios.post(featuresUrl, {
                query,
                variables
            }, {
                headers: {
                    "x-api-key": apiKey
                }
            }).then(res => {
                callback(res);
            }).catch(error => {
                console.log(error);
        });
    };

    render() {
        const {loading, list} = this.state;

        return (
            <List
                className="demo-loadmore-list"
                loading={loading}
                itemLayout="horizontal"
                loadMore={!loading}
                dataSource={list}
                renderItem={item => (
                    <List.Item actions={[<a>edit</a>, <a>more</a>]}>
                        <Skeleton title={item} loading={loading} active>
                            <List.Item.Meta
                                title={<a href="https://ant.design">{item}</a>}
                                description="Ant Design, a design language for background applications, is refined by Ant UED Team"
                            />
                            <div>content</div>
                        </Skeleton>
                    </List.Item>
                )}
            />
        );
    }
}

export default App;
